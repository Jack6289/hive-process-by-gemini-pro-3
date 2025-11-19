
import { ScanFinding } from '../types';
import { HiveGraph } from './inferenceEngine';

const SIG_NK = 0x6B6E; 
const SIG_DESTROYED = 0x5858; // 'XX'

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

    // We look for nk signatures anywhere in the data to catch unallocated/slack space too
    if (sig === SIG_NK) {
      
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
  
  const targetLeaf = parts[parts.length - 1].toLowerCase(); 
  const queryPath = parts.join('\\').toLowerCase();

  // --- PHASE 1: STANDARD STRUCTURED SCAN ---
  const foundOffsets = new Set<number>();

  let cursor = 0x0;
  while (cursor < len - 8) {
    if (view.getUint16(cursor, true) === SIG_NK) {
      const name = graph.readNodeName(cursor);
      if (name.toLowerCase().includes(targetLeaf)) {
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
  // Convert target leaf to ASCII bytes
  const asciiPattern: number[] = [];
  for(let i=0; i<targetLeaf.length; i++) asciiPattern.push(targetLeaf.charCodeAt(i));

  // Convert target leaf to UTF-16LE bytes (simple latin approximation)
  const utf16Pattern: number[] = [];
  for(let i=0; i<targetLeaf.length; i++) {
    utf16Pattern.push(targetLeaf.charCodeAt(i));
    utf16Pattern.push(0);
  }

  const rawMatches = [
    ...findBytePattern(data, asciiPattern), 
    ...findBytePattern(data, utf16Pattern)
  ];

  rawMatches.forEach(strOffset => {
    // A standard 'nk' record has the name at offset 0x4C (76)
    // We check backwards to see if this string belongs to a node structure
    const possibleNodeStart = strOffset - 0x4C;

    if (possibleNodeStart >= 0 && !foundOffsets.has(possibleNodeStart)) {
       
       const sig = view.getUint16(possibleNodeStart, true);
       
       if (sig === SIG_NK) {
          // Valid node, already processed in Phase 1
       } else if (sig === SIG_DESTROYED) {
          // Explicitly destroyed by HiveMind. Ignore to prevent re-detection.
          return; 
       } else {
          // Check 2: Signature is corrupted or missing, BUT length matches?
          // Name Length is at 0x48
          const nameLen = view.getUint16(possibleNodeStart + 0x48, true);
          
          // Heuristic: If the length field matches the string length we searched for
          // It is likely a RECOVERED KEY with a corrupted header.
          // Note: If nameLen is 0 (which we set on destroy now), this check fails, 
          // so the item is ignored. Perfect.
          
          let type: ScanFinding['type'] = 'DATA_REMNANT';
          let desc = "Found in unallocated space or deleted record.";
          let confidence = 0.3;

          if (nameLen > 0 && nameLen < 256) {
             type = 'RECOVERED_KEY';
             desc = "Header signature corrupted, but structure valid. Likely recoverable.";
             confidence = 0.7;
          }

          findings.push({
            id: `scrape-${strOffset}`,
            offset: possibleNodeStart, // Point to where the header SHOULD be
            length: 0x50 + targetLeaf.length, // Approx
            type: type,
            name: `[SCRAPED] ${targetLeaf}`,
            description: desc,
            confidence: confidence,
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
  });

  return findings;
};
