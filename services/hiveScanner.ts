
import { ScanFinding } from '../types';
import { HiveGraph } from './inferenceEngine';

const SIG_NK = 0x6B6E; 
const SIG_DESTROYED = 0x5858; // 'XX'
const SIG_HBIN = 0x6E696268;

export const repairKeyNode = (cellBytes: Uint8Array): Uint8Array | null => {
  if (cellBytes.length < 0x50) return null;
  
  const view = new DataView(cellBytes.buffer, cellBytes.byteOffset, cellBytes.byteLength);
  
  const sig = view.getUint16(0, true);
  if (sig !== SIG_NK) return null; 

  const flags = view.getUint16(0x02, true);
  const isCompressed = (flags & 0x20) !== 0; 

  let calculatedLen = 0;
  const maxLen = cellBytes.length - 0x4C; 
  
  if (isCompressed) {
     for (let i = 0; i < maxLen; i++) {
        const b = cellBytes[0x4C + i];
        if (b === 0 || b < 32 || b > 126) break; 
        calculatedLen++;
     }
  } else {
     for (let i = 0; i < maxLen; i+=2) {
        const val = view.getUint16(0x4C + i, true);
        if (val === 0) break;
        calculatedLen += 2;
     }
  }

  if (calculatedLen === 0) return null;

  const patched = new Uint8Array(cellBytes);
  const patchedView = new DataView(patched.buffer, patched.byteOffset, patched.byteLength);

  patchedView.setUint16(0x48, calculatedLen, true);
  patchedView.setUint16(0x4A, 0, true);
  patchedView.setInt32(0x30, -1, true);

  return patched;
};

const getBinRelativeOffset = (data: Uint8Array, absOffset: number): number => {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let cursor = absOffset & ~0xFFF; 
  
  for(let i=0; i<16; i++) {
     if (cursor < 0) break;
     if (cursor + 4 <= data.length && view.getUint32(cursor, true) === SIG_HBIN) {
         return absOffset - cursor;
     }
     cursor -= 4096;
  }
  
  cursor = absOffset;
  const limit = Math.max(0, absOffset - 65536);
  while(cursor >= limit) {
     if (cursor + 4 <= data.length && view.getUint32(cursor, true) === SIG_HBIN) {
         return absOffset - cursor;
     }
     cursor -= 4; 
  }

  return -1;
};

export const scanHiveForAnomalies = (data: Uint8Array): ScanFinding[] => {
  const findings: ScanFinding[] = [];
  const graph = new HiveGraph(data);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const len = data.length;

  // v3.1 Active Logic: Build Reachability Map to find DKOM keys
  const reachableOffsets = graph.buildReachabilityMap();
  const rootOffset = graph.getRootOffset(); // Get Root Key Offset for Protection

  // SAFETY CIRCUIT BREAKER:
  // If we only found a handful of reachable keys in a large file, the tree walk likely failed.
  // In this case, flagging everything else as "Unlinked" is a False Positive.
  // We disable DKOM detection if reachable count is suspicious (< 0.1% of estimated keys or absolute low).
  const estimatedKeys = len / 0x100; // Crude estimate
  const isTreeWalkSuspect = reachableOffsets.size < 50 && len > 0x10000; 
  
  if (isTreeWalkSuspect) {
      console.warn("Hive Scanner Warning: Reachability Map too small. Disabling DKOM to prevent false positives.");
  }

  // OPTIMIZATION: Scan in 8-byte alignment steps.
  // Registry cells are 8-byte aligned relative to bin start.
  let cursor = 0x0; 
  
  while (cursor < len - 8) {
    const sig = view.getUint16(cursor, true);

    let allocationStatus: 'Allocated' | 'Free' | 'Unknown' = 'Unknown';
    if (cursor >= 4) {
       const cellSize = view.getInt32(cursor - 4, true);
       allocationStatus = cellSize < 0 ? 'Allocated' : 'Free';
    }

    // PROTECT ROOT KEY: Never flag the root key
    if (cursor === rootOffset) {
        cursor += 8;
        continue;
    }

    if (sig === SIG_DESTROYED) {
       findings.push({
          id: `destroyed-${cursor}`,
          offset: cursor,
          length: 80, 
          type: 'DESTROYED_ARTIFACT',
          name: "[DESTROYED]",
          description: "User-patched artifact (Signature 'XX' detected)",
          confidence: 1.0,
          isDeleted: true,
          allocationStatus,
          binRelativeOffset: getBinRelativeOffset(data, cursor)
       });
    }
    else if (sig === SIG_NK) {
      const nameLen = view.getUint16(cursor + 0x48, true);
      const classLen = view.getUint16(cursor + 0x4A, true); // Offset 0x4A
      const flags = view.getUint16(cursor + 0x02, true);
      
      if (nameLen > 0 && nameLen < 4096 && cursor + 0x4C + nameLen <= len) {
        const heuristics = graph.analyzeHeuristics(cursor);
        const name = graph.readNodeName(cursor);
        const parentCID = view.getInt32(cursor + 0x10, true);
        const resolution = graph.resolvePath(cursor);

        let type: ScanFinding['type'] | null = null;
        let desc = "";
        
        // 1. NULL-BYTE HIDING (v3.1 Active Check)
        // OPTIMIZATION: Avoid allocation slice. Check manually.
        let embeddedNullIndex = -1;
        // Only relevant for ASCII (Compressed) keys, UTF16 has 00 naturally
        if ((flags & 0x20) && nameLen > 0) { 
             for(let k=0; k<nameLen; k++) {
                if (data[cursor + 0x4C + k] === 0) {
                    embeddedNullIndex = k;
                    break;
                }
             }
        }
        
        if (embeddedNullIndex !== -1) {
             type = 'ROOTKIT_NULL_EMBEDDED';
             desc = `Detected Null-Byte Terminator at pos ${embeddedNullIndex}. Hides suffix from Windows API.`;
        }

        // 2. CLASS DATA INJECTION (v3.1 Active Check)
        else if (classLen > 0) {
             // Class Data is rare. If it contains binary garbage, it's suspicious.
             const classOffset = view.getInt32(cursor + 0x30, true);
             if (classOffset !== -1) {
                 // Note: We don't fully resolve class offset here to save time, 
                 // but mere presence of Class Data in non-standard keys is flagged.
                 // Heuristic: If name is standard (not Shell/COM), but has Class Data.
                 if (!name.includes("CLSID") && !name.includes("Interface")) {
                     type = 'ROOTKIT_CLASS_INJECTION';
                     desc = `Abnormal Class Data (${classLen} bytes) detected on standard key. Potential payload injection.`;
                 }
             }
        }

        // 3. UNLINKED / DKOM (v3.1 Active Check)
        // CHECK SAFETY BREAKER FIRST
        else if (!isTreeWalkSuspect && !reachableOffsets.has(cursor) && allocationStatus === 'Allocated') {
             // Key exists, is marked allocated, has valid header, but tree walk didn't find it.
             type = 'ROOTKIT_UNLINKED_DKOM';
             desc = "DKOM Detected: Key exists in binary but is unlinked from Registry Tree.";
        }

        // Legacy Checks
        else if (heuristics.some(h => h.includes("Virtualization") || h.includes("Ghost"))) {
          type = 'VIRTUALIZED';
          desc = "Ghost/Virtualization artifact detected.";
        } else if (heuristics.some(h => h.includes("Security") || h.includes("DACL"))) {
          type = 'HIDDEN';
          desc = "ACL Cloaking / Hidden Key.";
        } else if (heuristics.some(h => h.includes("Corruption") || h.includes("Timestamp"))) {
          type = 'CORRUPT';
          desc = "Structural Corruption or Timestamp Anomaly.";
        }
        
        if (type) {
          findings.push({
            id: `anom-${cursor}`,
            offset: cursor,
            length: 0x50 + nameLen,
            type: type,
            name: name || "[UNREADABLE]",
            description: desc,
            confidence: type.includes('ROOTKIT') ? 1.0 : 0.85,
            allocationStatus,
            binRelativeOffset: getBinRelativeOffset(data, cursor),
            inference: {
              resolvedPath: resolution.path,
              pathConfidence: 1.0,
              heuristicWarnings: heuristics,
              parentCellIndex: parentCID,
              traceSteps: resolution.steps
            }
          });
        }
      }
    }
    cursor += 8; // Step alignment
  }

  return findings;
};

const findBytePattern = (data: Uint8Array, pattern: number[]): number[] => {
  const offsets: number[] = [];
  const len = data.length;
  const patLen = pattern.length;
  
  for (let i = 0; i < len - patLen; i++) {
    let match = true;
    for (let j = 0; j < patLen; j++) {
      if (data[i + j] !== pattern[j]) {
        match = false;
        break;
      }
    }
    if (match) offsets.push(i);
  }
  return offsets;
};

export const searchHive = (data: Uint8Array, query: string): ScanFinding[] => {
  const findings: ScanFinding[] = [];
  const graph = new HiveGraph(data);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const len = data.length;

  const parts = query.split(/[\\/]/).filter(p => p.length > 0);
  if (parts.length === 0) return [];
  
  const targetLeaf = parts[parts.length - 1]; 
  const queryPath = parts.join('\\').toLowerCase();

  const foundOffsets = new Set<number>();
  const targetLeafLower = targetLeaf.toLowerCase();

  let cursor = 0x0;
  while (cursor < len - 8) {
    if (view.getUint16(cursor, true) === SIG_NK) {
      const name = graph.readNodeName(cursor);
      
      let allocationStatus: 'Allocated' | 'Free' | 'Unknown' = 'Unknown';
      if (cursor >= 4) {
         const cellSize = view.getInt32(cursor - 4, true);
         allocationStatus = cellSize < 0 ? 'Allocated' : 'Free';
      }

      if (name.toLowerCase().includes(targetLeafLower)) {
        foundOffsets.add(cursor);
        
        const resolution = graph.resolvePath(cursor, parts.length + 2);
        const fullPath = resolution.path.toLowerCase();
        
        let isPathMatch = true;
        if (parts.length > 1) {
             isPathMatch = fullPath.includes(queryPath);
        }

        findings.push({
             id: `search-${cursor}`,
             offset: cursor,
             length: 0x50 + name.length,
             type: 'SEARCH_MATCH',
             name: name,
             description: isPathMatch 
                ? "Deep Path Verified" 
                : `Name Match (Path divergence detected)`,
             confidence: isPathMatch ? 1.0 : 0.5,
             allocationStatus,
             binRelativeOffset: getBinRelativeOffset(data, cursor),
             inference: {
               resolvedPath: resolution.path || "UNABLE_TO_RESOLVE",
               pathConfidence: isPathMatch ? 1.0 : 0.0,
               heuristicWarnings: isPathMatch ? [] : ["Path divergence from query"],
               parentCellIndex: view.getInt32(cursor + 0x10, true),
               traceSteps: resolution.steps
             }
        });
      }
    }
    cursor += 8; // Optimization: Step 8
  }

  const variants = new Set([
    targetLeaf, 
    targetLeaf.toLowerCase(), 
    targetLeaf.toUpperCase(),
    targetLeaf.charAt(0).toUpperCase() + targetLeaf.slice(1).toLowerCase()
  ]);

  const rawMatches: number[] = [];

  variants.forEach(v => {
     const ascii: number[] = [];
     for(let i=0; i<v.length; i++) ascii.push(v.charCodeAt(i));
     
     const utf16: number[] = [];
     for(let i=0; i<v.length; i++) { utf16.push(v.charCodeAt(i)); utf16.push(0); }

     rawMatches.push(...findBytePattern(data, ascii));
     rawMatches.push(...findBytePattern(data, utf16));
  });

  const uniqueMatches = Array.from(new Set(rawMatches));

  uniqueMatches.forEach(strOffset => {
    const possibleNodeStart = strOffset - 0x4C;

    if (possibleNodeStart >= 0 && !foundOffsets.has(possibleNodeStart)) {
       
       const sig = view.getUint16(possibleNodeStart, true);
       
       let allocationStatus: 'Allocated' | 'Free' | 'Unknown' = 'Unknown';
       if (possibleNodeStart >= 4) {
          const cellSize = view.getInt32(possibleNodeStart - 4, true);
          allocationStatus = cellSize < 0 ? 'Allocated' : 'Free';
       }
       
       const relativeOffset = getBinRelativeOffset(data, possibleNodeStart);

       if (sig === SIG_NK) {
          // Valid node
       } else if (sig === SIG_DESTROYED) {
          findings.push({
            id: `destroyed-${possibleNodeStart}`,
            offset: possibleNodeStart,
            length: 80,
            type: 'DESTROYED_ARTIFACT',
            name: `[DESTROYED] ${targetLeaf}`,
            description: "User-patched artifact.",
            confidence: 1.0,
            isDeleted: true,
            allocationStatus,
            binRelativeOffset: relativeOffset
          });
       } else {
          const nameLen = view.getUint16(possibleNodeStart + 0x48, true);
          const flags = view.getUint16(possibleNodeStart + 0x02, true);
          
          let type: ScanFinding['type'] = 'DATA_REMNANT';
          let desc = "Found in unallocated space or deleted record.";
          let confidence = 0.3;

          if (nameLen > 0 && nameLen < 256 && flags < 0x100) {
             type = 'RECOVERED_KEY';
             desc = "Header signature corrupted, but structure valid.";
             confidence = 0.7;
          }

          if (nameLen > 0) { 
              findings.push({
                id: `scrape-${strOffset}`,
                offset: possibleNodeStart, 
                length: 0x50 + targetLeaf.length, 
                type: type,
                name: `[SCRAPED] ${targetLeaf}`,
                description: desc,
                confidence: confidence,
                allocationStatus,
                binRelativeOffset: relativeOffset,
                inference: {
                  resolvedPath: "FRAGMENTED_DATA",
                  pathConfidence: 0,
                  heuristicWarnings: ["Signature Mismatch (Corrupted Header)", "Recovered via String Scraping"],
                  parentCellIndex: 0,
                  traceSteps: ["Raw string search hit", "Back-trace to header failed or corrupted"]
                }
              });
          }
       }
    }
  });

  return findings;
};
