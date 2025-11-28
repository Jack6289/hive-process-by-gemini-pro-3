
import { ScanFinding } from '../types';
import { HiveGraph } from './inferenceEngine';

const SIG_NK = 0x6B6E; 
const SIG_DESTROYED = 0x5858; // 'XX'
const SIG_HBIN = 0x6E696268;
const SIG_VK = 0x6B76; // 'vk' Value Key

// v8.0 Safety: Critical Boot Paths that MUST NOT be auto-deleted
const CRITICAL_PATHS = [
    /ControlSet[0-9]*\\Control$/i, // Strict End Anchor
    /ControlSet[0-9]*\\Services$/i,   
    /Microsoft\\Windows NT\\CurrentVersion$/i,
    /Microsoft\\Windows\\CurrentVersion$/i,
    /SAM\\Domains/i,
    /MountedDevices/i,
    /BCD00000000/i
];

// v9.0 Sysinternals Autoruns Logic: Known ASEP (Auto-Start Extensibility Points)
const AUTORUNS_ASEPS = [
    /Microsoft\\Windows\\CurrentVersion\\Run/i,
    /Microsoft\\Windows\\CurrentVersion\\RunOnce/i,
    /Microsoft\\Windows\\CurrentVersion\\RunServices/i,
    /Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify/i,
    /Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit/i,
    /Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options/i, // IFEO
    /Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs/i,
    /ControlSet[0-9]*\\Control\\Session Manager\\AppCertDlls/i,
    /ControlSet[0-9]*\\Services\\.*\\Parameters/i, // Service Parameters
    /Software\\Microsoft\\Active Setup\\Installed Components/i,
    /Software\\Classes\\Exefile\\Shell\\Open\\Command/i
];

// v10.0 MSI Installer Paths (Global)
const INSTALLER_PATHS_HKLM = [
    /Microsoft\\Windows\\CurrentVersion\\Uninstall/i,
    /Microsoft\\Windows\\CurrentVersion\\Installer\\UserData/i,
    /Classes\\Installer\\Products/i,
    /Classes\\Installer\\UpgradeCodes/i,
    /Classes\\Installer\\Features/i
];

// v10.1 User-Specific Installer Paths (NTUSER.DAT)
const INSTALLER_PATHS_HKCU = [
    /Software\\Microsoft\\Installer\\Products/i,
    /Software\\Microsoft\\Installer\\UpgradeCodes/i,
    /Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall/i
];

const isCriticalPath = (path: string): boolean => {
    return CRITICAL_PATHS.some(regex => regex.test(path));
};

const isPersistencePath = (path: string): boolean => {
    return AUTORUNS_ASEPS.some(regex => regex.test(path));
};

// v10.1: Context-Aware Path Check
const isInstallerPath = (path: string, hiveType: string): boolean => {
    if (hiveType === 'NTUSER.DAT') {
        return INSTALLER_PATHS_HKCU.some(regex => regex.test(path));
    }
    // Default to HKLM/SOFTWARE logic
    return INSTALLER_PATHS_HKLM.some(regex => regex.test(path));
};

// v10.0 Helper: Read Values for a Key to find DisplayName/ProductName
const readValuesForKey = (view: DataView, keyOffset: number, data: Uint8Array, graph: HiveGraph): string[] => {
    const values: string[] = [];
    const valListIndex = view.getInt32(keyOffset + 0x28, true);
    const valCount = view.getUint32(keyOffset + 0x24, true);

    if (valCount > 0 && valCount < 1000 && valListIndex !== -1) {
        const listOffset = graph.resolveCellOffset(valListIndex);
        if (listOffset) {
            for (let i = 0; i < valCount; i++) {
                const vkOffsetRef = view.getUint32(listOffset + 4 + (i * 4), true);
                const vkOffset = graph.resolveCellOffset(vkOffsetRef);
                if (vkOffset && view.getUint16(vkOffset, true) === SIG_VK) {
                    const dataLen = view.getUint32(vkOffset + 0x0C, true);
                    const dataOffsetRef = view.getUint32(vkOffset + 0x08, true);
                    
                    // Check if data is inline (MSB set in len)
                    if (dataLen & 0x80000000) {
                         // Inline data - usually too short for meaningful names
                    } else {
                         const dataRealOffset = graph.resolveCellOffset(dataOffsetRef);
                         if (dataRealOffset && dataLen > 0 && dataLen < 256) {
                             // Try to read ASCII/Unicode string from data cell
                             let valStr = "";
                             for(let k=0; k<dataLen; k++) {
                                 const b = data[dataRealOffset + 4 + k]; // +4 for cell header
                                 if (b >= 32 && b <= 126) valStr += String.fromCharCode(b);
                             }
                             if (valStr.length > 3) values.push(valStr);
                         }
                    }
                }
            }
        }
    }
    return values;
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

  const reachableOffsets = graph.buildReachabilityMap();
  const rootOffset = graph.getRootOffset();

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
      const classLen = view.getUint16(cursor + 0x4A, true); 
      const flags = view.getUint16(cursor + 0x02, true);
      const subkeyCount = view.getUint32(cursor + 0x14, true);
      
      if (nameLen > 0 && nameLen < 4096 && cursor + 0x4C + nameLen <= len) {
        const heuristics = graph.analyzeHeuristics(cursor);
        const name = graph.readNodeName(cursor);
        const parentCID = view.getInt32(cursor + 0x10, true);
        const resolution = graph.resolvePath(cursor);
        
        const isCritical = isCriticalPath(resolution.path);
        const isPersistence = isPersistencePath(resolution.path);

        let type: ScanFinding['type'] | null = null;
        let desc = "";
        let confidence = 0.85;
        
        if (isPersistence && !isCritical) {
            type = 'PERSISTENCE_MECHANISM';
            desc = `Sysinternals ASEP: Key located in known auto-start path (${resolution.path}).`;
            confidence = 0.95;
        }
        else if ((flags & 0x20) && nameLen > 0) { 
             let embeddedNull = false;
             for(let k=0; k<nameLen; k++) {
                if (data[cursor + 0x4C + k] === 0) {
                    embeddedNull = true;
                    break;
                }
             }
             if (embeddedNull) {
                type = 'ROOTKIT_NULL_EMBEDDED';
                desc = `Detected Null-Byte Terminator. Hides suffix from Windows API.`;
                confidence = 1.0; 
             }
        }
        else if (classLen > 0 && !type) {
             const classOffset = view.getInt32(cursor + 0x30, true);
             if (classOffset !== -1) {
                 if (!name.includes("CLSID") && !name.includes("Interface")) {
                     type = 'ROOTKIT_CLASS_INJECTION';
                     desc = `Abnormal Class Data (${classLen} bytes) detected.`;
                     confidence = 0.9;
                 }
             }
        }
        else if (!isTreeWalkSuspect && !reachableOffsets.has(cursor) && allocationStatus === 'Allocated' && !type) {
             type = 'ROOTKIT_UNLINKED_DKOM';
             desc = "Potential DKOM Anomaly: Key is unlinked from Registry Tree.";
             confidence = 0.4; 
        }
        else if (!type && heuristics.some(h => h.includes("Virtualization") || h.includes("Ghost"))) {
          type = 'VIRTUALIZED';
          desc = "Ghost/Virtualization artifact detected.";
        } else if (!type && heuristics.some(h => h.includes("Security") || h.includes("DACL"))) {
          type = 'HIDDEN';
          desc = "ACL Cloaking / Hidden Key.";
        } else if (!type && heuristics.some(h => h.includes("Corruption") || h.includes("Timestamp"))) {
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
    cursor += 8; 
  }

  return findings;
};

// v10.0: Program Troubleshooter Logic
export const searchProgramArtifacts = (data: Uint8Array, programName: string, hiveType: string = 'SOFTWARE'): ScanFinding[] => {
  const findings: ScanFinding[] = [];
  const graph = new HiveGraph(data);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const len = data.length;
  
  const queryLower = programName.toLowerCase();
  
  let cursor = 0x0;
  while (cursor < len - 8) {
    if (view.getUint16(cursor, true) === SIG_NK) {
      const name = graph.readNodeName(cursor);
      const subkeyCount = view.getUint32(cursor + 0x14, true);

      // 1. Resolve Path
      const resolution = graph.resolvePath(cursor, 8);
      
      // v10.1: Smart Check based on Hive Type
      const isInstaller = isInstallerPath(resolution.path, hiveType);
      
      let isMatch = false;
      let desc = "";
      let confidence = 0.0;

      // Match Strategy A: Key Name Match
      if (name.toLowerCase().includes(queryLower)) {
          isMatch = true;
          desc = "Program Name Match in Key";
          confidence = 0.8;
      }
      
      // Match Strategy B: Installer/Uninstall GUID Deep Scan
      if (!isMatch && isInstaller) {
          // If inside an Installer path, check values for DisplayName/ProductName
          const values = readValuesForKey(view, cursor, data, graph);
          if (values.some(v => v.toLowerCase().includes(queryLower))) {
              isMatch = true;
              desc = "MSI Artifact: Value Data matches Program Name";
              confidence = 1.0;
          }
      }

      if (isMatch) {
          const isCritical = isCriticalPath(resolution.path);
          
          findings.push({
             id: `msi-${cursor}`,
             offset: cursor,
             length: 0x50 + name.length,
             type: 'INSTALLER_ARTIFACT',
             name: name,
             description: desc + (isInstaller ? " (Installer Database)" : ""),
             confidence: confidence,
             allocationStatus: 'Allocated',
             binRelativeOffset: getBinRelativeOffset(data, cursor),
             inference: {
               resolvedPath: resolution.path || "UNABLE_TO_RESOLVE",
               pathConfidence: 1.0,
               heuristicWarnings: [],
               parentCellIndex: view.getInt32(cursor + 0x10, true),
               traceSteps: resolution.steps
             },
             isSystemCritical: isCritical,
             subkeyCount: subkeyCount,
             relatedProgramName: programName
          });
      }
    }
    cursor += 8;
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
        const resolution = graph.resolvePath(cursor, parts.length + 2);
        const fullPath = resolution.path.toLowerCase();
        let isPathMatch = true;
        if (parts.length > 1) {
             isPathMatch = fullPath.includes(queryPath);
        }
        const isCritical = isCriticalPath(resolution.path);
        const subkeyCount = view.getUint32(cursor + 0x14, true);
        
        let type: ScanFinding['type'] = 'SEARCH_MATCH';
        let desc = isPathMatch ? "Deep Path Verified" : `Name Match (Path divergence detected)`;
        let confidence = isPathMatch ? 1.0 : 0.5;

        if (isPersistencePath(resolution.path)) {
            type = 'PERSISTENCE_MECHANISM';
            desc = "MATCH + PERSISTENCE: Key in auto-start path.";
            confidence = 0.95;
        }
        const nameLen = view.getUint16(cursor + 0x48, true);
        const flags = view.getUint16(cursor + 0x02, true);
        if ((flags & 0x20) && nameLen > 0) {
             let embeddedNull = false;
             for(let k=0; k<nameLen; k++) {
                if (data[cursor + 0x4C + k] === 0) { embeddedNull = true; break; }
             }
             if (embeddedNull) {
                type = 'ROOTKIT_NULL_EMBEDDED';
                desc = "MATCH + ROOTKIT: Null-Byte Terminator detected.";
                confidence = 1.0;
             }
        }
        const classLen = view.getUint16(cursor + 0x4A, true);
        if (classLen > 0 && type === 'SEARCH_MATCH') {
             const classOffset = view.getInt32(cursor + 0x30, true);
             if (classOffset !== -1 && !name.includes("CLSID") && !name.includes("Interface")) {
                 type = 'ROOTKIT_CLASS_INJECTION';
                 desc = "MATCH + INJECTION: Abnormal Class Data detected.";
                 confidence = 0.9;
             }
        }

        findings.push({
             id: `search-${cursor}`,
             offset: cursor,
             length: 0x50 + name.length,
             type: type,
             name: name,
             description: desc,
             confidence: confidence,
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
             subkeyCount: subkeyCount,
             isSearchMatch: true 
        });
      }
    }
    cursor += 8; 
  }
  return findings;
};
