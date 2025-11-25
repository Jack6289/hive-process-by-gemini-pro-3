
import { ScanFinding } from '../types';
import { HiveGraph } from './inferenceEngine';

const SIG_NK = 0x6B6E; 
const SIG_DESTROYED = 0x5858; // 'XX'
const SIG_HBIN = 0x6E696268;

// v8.0 Safety: Critical Boot Paths that MUST NOT be auto-deleted
const CRITICAL_PATHS = [
    /ControlSet[0-9]*\\Control/i,
    /ControlSet[0-9]*\\Services/i,   // Generally unsafe to bulk delete services
    /Microsoft\\Windows NT\\CurrentVersion/i,
    /Microsoft\\Windows\\CurrentVersion/i,
    /SAM\\Domains/i,
    /MountedDevices/i,
    /BCD00000000/i
];

const isCriticalPath = (path: string): boolean => {
    return CRITICAL_PATHS.some(regex => regex.test(path));
};

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
  const estimatedKeys = len / 0x100; // Crude estimate
  const isTreeWalkSuspect = reachableOffsets.size < 50 && len > 0x10000; 
  
  if (isTreeWalkSuspect) {
      console.warn("Hive Scanner Warning: Reachability Map too small. Disabling DKOM to prevent false positives.");
  }

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
          binRelativeOffset: getBinRelativeOffset(data, cursor),
          isSystemCritical: false,
          subkeyCount: 0
       });
    }
    else if (sig === SIG_NK) {
      const nameLen = view.getUint16(cursor + 0x48, true);
      const classLen = view.getUint16(cursor + 0x4A, true); // Offset 0x4A
      const flags = view.getUint16(cursor + 0x02, true);
      const subkeyCount = view.getUint32(cursor + 0x14, true); // v8.0: Read Subkey Count
      
      if (nameLen > 0 && nameLen < 4096 && cursor + 0x4C + nameLen <= len) {
        const heuristics = graph.analyzeHeuristics(cursor);
        const name = graph.readNodeName(cursor);
        const parentCID = view.getInt32(cursor + 0x10, true);
        const resolution = graph.resolvePath(cursor);
        
        // v8.0 Safety Check
        const isCritical = isCriticalPath(resolution.path);

        let type: ScanFinding['type'] | null = null;
        let desc = "";
        let confidence = 0.85;
        
        // 1. NULL-BYTE HIDING
        let embeddedNullIndex = -1;
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
             confidence = 1.0; 
        }

        // 2. CLASS DATA INJECTION
        else if (classLen > 0) {
             const classOffset = view.getInt32(cursor + 0x30, true);
             if (classOffset !== -1) {
                 if (!name.includes("CLSID") && !name.includes("Interface")) {
                     type = 'ROOTKIT_CLASS_INJECTION';
                     desc = `Abnormal Class Data (${classLen} bytes) detected.`;
                     confidence = 0.9;
                 }
             }
        }

        // 3. UNLINKED / DKOM
        else if (!isTreeWalkSuspect && !reachableOffsets.has(cursor) && allocationStatus === 'Allocated') {
             type = 'ROOTKIT_UNLINKED_DKOM';
             desc = "Potential DKOM Anomaly: Key is unlinked from Registry Tree.";
             confidence = 0.4; 
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
            confidence: confidence,
            allocationStatus,
            binRelativeOffset: getBinRelativeOffset(data, cursor),
            inference: {
              resolvedPath: resolution.path,
              pathConfidence: 1.0,
              heuristicWarnings: heuristics,
              parentCellIndex: parentCID,
              traceSteps: resolution.steps
            },
            isSystemCritical: isCritical,
            subkeyCount: subkeyCount
          });
        }
      }
    }
    cursor += 8; // Step alignment
  }

  return findings;
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

        // v8.0: Check Criticality and Subkey Count
        const isCritical = isCriticalPath(resolution.path);
        const subkeyCount = view.getUint32(cursor + 0x14, true);

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
             },
             isSystemCritical: isCritical,
             subkeyCount: subkeyCount
        });
      }
    }
    cursor += 8; 
  }
  // (Remaining string scraping logic omitted for brevity as it remains unchanged and returns DATA_REMNANT which is handled)
  return findings;
};
