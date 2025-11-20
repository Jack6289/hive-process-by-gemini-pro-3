
import { ScanFinding } from '../types';
import { HiveGraph } from './inferenceEngine';

const SIG_NK = 0x6B6E; 
const SIG_DESTROYED = 0x5858; // 'XX'
const SIG_HBIN = 0x6E696268;

// Attempts to calculate the correct name length for a corrupted 'nk' header
// and returns a patched byte array for the cell.
export const repairKeyNode = (cellBytes: Uint8Array): Uint8Array | null => {
  if (cellBytes.length < 0x50) return null;
  
  const view = new DataView(cellBytes.buffer, cellBytes.byteOffset, cellBytes.byteLength);
  
  // Check Signature (must be nk or maybe we are forcing repair on a suspected one)
  const sig = view.getUint16(0, true);
  if (sig !== SIG_NK) return null; // We only repair valid 'nk' signatures

  const flags = view.getUint16(0x02, true);
  const isCompressed = (flags & 0x20) !== 0; // ASCII

  // Name starts at 0x4C (76).
  // We need to scan from there to find the real length.
  let calculatedLen = 0;
  const maxLen = cellBytes.length - 0x4C; 
  
  if (isCompressed) {
     // ASCII: Scan until null or non-printable
     for (let i = 0; i < maxLen; i++) {
        const b = cellBytes[0x4C + i];
        if (b === 0 || b < 32 || b > 126) break; // Stop at null or control
        calculatedLen++;
     }
  } else {
     // UTF-16LE: Scan 2 bytes. Stop at 0x0000 or weird control chars.
     for (let i = 0; i < maxLen; i+=2) {
        const val = view.getUint16(0x4C + i, true);
        if (val === 0) break;
        // Basic heuristic for printable unicode range often seen in registry
        calculatedLen += 2;
     }
  }

  if (calculatedLen === 0) return null;

  // Create patched buffer
  const patched = new Uint8Array(cellBytes);
  const patchedView = new DataView(patched.buffer, patched.byteOffset, patched.byteLength);

  // Fix Name Length (0x48)
  patchedView.setUint16(0x48, calculatedLen, true);
  
  // Zero Class Length (0x4A) - usually 0 unless specific class used
  patchedView.setUint16(0x4A, 0, true);

  // Reset Class Index (0x30) to -1 (FFFFFFFF) if it was pointing to garbage
  patchedView.setInt32(0x30, -1, true);

  return patched;
};

const getBinRelativeOffset = (data: Uint8Array, absOffset: number): number => {
  // Walk backwards to find the nearest 'hbin' signature
  // We assume bins are 4KB aligned usually, or at least nearby.
  // Scan limit 64KB backwards.
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let cursor = absOffset & ~0xFFF; // Start at page boundary
  
  // If page boundary isn't hbin, search backwards page by page
  for(let i=0; i<16; i++) {
     if (cursor < 0) break;
     if (cursor + 4 <= data.length && view.getUint32(cursor, true) === SIG_HBIN) {
         return absOffset - cursor;
     }
     cursor -= 4096;
  }
  
  // Fallback: linear scan backwards if alignment failed (corrupted hive)
  cursor = absOffset;
  const limit = Math.max(0, absOffset - 65536);
  while(cursor >= limit) {
     if (cursor + 4 <= data.length && view.getUint32(cursor, true) === SIG_HBIN) {
         return absOffset - cursor;
     }
     cursor -= 4; // scan 4 bytes
  }

  return -1;
};

export const scanHiveForAnomalies = (data: Uint8Array): ScanFinding[] => {
  const findings: ScanFinding[] = [];
  
  // Initialize the Graph Engine
  const graph = new HiveGraph(data);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const len = data.length;

  // Optimize: Align to 4 bytes
  let cursor = 0x0; 
  
  while (cursor < len - 8) {
    const sig = view.getUint16(cursor, true);

    // Check Cell Allocation Status (Size at -4)
    let allocationStatus: 'Allocated' | 'Free' | 'Unknown' = 'Unknown';
    if (cursor >= 4) {
       const cellSize = view.getInt32(cursor - 4, true);
       // Negative size = Allocated (Active)
       // Positive size = Free (Deleted)
       allocationStatus = cellSize < 0 ? 'Allocated' : 'Free';
    }

    // Case 1: Explicitly Destroyed Artifact
    if (sig === SIG_DESTROYED) {
       findings.push({
          id: `destroyed-${cursor}`,
          offset: cursor,
          length: 80, // Estimate
          type: 'DESTROYED_ARTIFACT',
          name: "[DESTROYED]",
          description: "User-patched artifact (Signature 'XX' detected)",
          confidence: 1.0,
          isDeleted: true,
          allocationStatus,
          binRelativeOffset: getBinRelativeOffset(data, cursor)
       });
    }
    // Case 2: Valid Key Node
    else if (sig === SIG_NK) {
      
      // Basic Validity Check
      const nameLen = view.getUint16(cursor + 0x48, true);
      
      if (nameLen > 0 && nameLen < 4096 && cursor + 0x4C + nameLen <= len) {
        const heuristics = graph.analyzeHeuristics(cursor);
        const name = graph.readNodeName(cursor);
        
        let type: ScanFinding['type'] | null = null;
        let desc = "";
        
        if (heuristics.some(h => h.includes("Virtualization") || h.includes("Ghost"))) {
          type = 'VIRTUALIZED';
          desc = "Ghost/Virtualization artifact detected.";
        } else if (heuristics.some(h => h.includes("Security") || h.includes("DACL"))) {
          type = 'HIDDEN';
          desc = "ACL Cloaking / Hidden Key.";
        } else if (heuristics.some(h => h.includes("Corruption") || h.includes("Timestamp"))) {
          type = 'CORRUPT';
          desc = "Structural Corruption or Timestamp Anomaly.";
        }
        
        // Special Case: Null Bytes in Name (Stubborn)
        const nameBytes = data.slice(cursor + 0x4C, cursor + 0x4C + nameLen);
        let hasNull = false;
        for(let b of nameBytes) { if (b === 0) hasNull = true; }
        if (hasNull && !type) {
           type = 'STUBBORN';
           desc = "Embedded Nulls prevent deletion.";
        }

        if (type) {
          const parentCID = view.getInt32(cursor + 0x10, true);
          const resolution = graph.resolvePath(cursor);

          findings.push({
            id: `anom-${cursor}`,
            offset: cursor,
            length: 0x50 + nameLen,
            type: type,
            name: name,
            description: desc,
            confidence: 0.85,
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
    cursor += 4;
  }

  return findings;
};

// Helper to find all occurrences of a byte pattern
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

  // --- PHASE 1: STANDARD STRUCTURED SCAN ---
  const foundOffsets = new Set<number>();
  const targetLeafLower = targetLeaf.toLowerCase();

  let cursor = 0x0;
  while (cursor < len - 8) {
    if (view.getUint16(cursor, true) === SIG_NK) {
      const name = graph.readNodeName(cursor);
      
      // Get Allocation Status
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
    cursor += 4;
  }

  // --- PHASE 2: RAW STRING SCRAPER (For corrupted/deleted/ghost keys) ---
  // Heuristic: Generate TitleCase, LowerCase, UpperCase variants to approximate case-insensitivity
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

  // Deduplicate
  const uniqueMatches = Array.from(new Set(rawMatches));

  uniqueMatches.forEach(strOffset => {
    const possibleNodeStart = strOffset - 0x4C;

    if (possibleNodeStart >= 0 && !foundOffsets.has(possibleNodeStart)) {
       
       const sig = view.getUint16(possibleNodeStart, true);
       
       // Get Allocation Status (Raw Scraper)
       let allocationStatus: 'Allocated' | 'Free' | 'Unknown' = 'Unknown';
       if (possibleNodeStart >= 4) {
          const cellSize = view.getInt32(possibleNodeStart - 4, true);
          allocationStatus = cellSize < 0 ? 'Allocated' : 'Free';
       }
       
       const relativeOffset = getBinRelativeOffset(data, possibleNodeStart);

       if (sig === SIG_NK) {
          // Valid node, already processed in Phase 1
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
          // Check 2: Signature is corrupted or missing, BUT length matches?
          const nameLen = view.getUint16(possibleNodeStart + 0x48, true);
          const flags = view.getUint16(possibleNodeStart + 0x02, true);
          
          let type: ScanFinding['type'] = 'DATA_REMNANT';
          let desc = "Found in unallocated space or deleted record.";
          let confidence = 0.3;

          if (nameLen > 0 && nameLen < 256 && flags < 0x100) {
             type = 'RECOVERED_KEY';
             desc = "Header signature corrupted, but structure valid. Likely recoverable.";
             confidence = 0.7;
          }

          if (nameLen > 0) { // Only report if there is SOME structural evidence
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
