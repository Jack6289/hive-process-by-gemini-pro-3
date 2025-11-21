
import { ScanFinding } from '../types';

const SIG_HBIN = 0x6E696268; // 'hbin'
const SIG_NK = 0x6B6E;
const BIN_START = 0x1000;

interface BinMap {
  logicalStart: number;
  physicalOffset: number;
  size: number;
}

export class HiveGraph {
  private data: Uint8Array;
  private view: DataView;
  private binMap: BinMap[] = [];

  constructor(data: Uint8Array) {
    this.data = data;
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.buildBinIndex();
  }

  private buildBinIndex() {
    let cursor = BIN_START;
    const len = this.data.length;

    while (cursor < len - 32) {
      // Check for hbin signature
      const sig = this.view.getUint32(cursor, true);
      if (sig !== SIG_HBIN) {
        break; 
      }

      const offsetRelative = this.view.getUint32(cursor + 0x04, true);
      const size = this.view.getUint32(cursor + 0x08, true);

      this.binMap.push({
        logicalStart: offsetRelative,
        physicalOffset: cursor,
        size: size
      });

      if (size === 0) break; 
      cursor += size;
    }

    // Optimization: Sort bin map by logical start to enable Binary Search
    this.binMap.sort((a, b) => a.logicalStart - b.logicalStart);
  }

  public resolveCellOffset(cellIndex: number): number | null {
    // OPTIMIZATION: Binary Search O(log N) instead of Linear Scan O(N)
    // This prevents freezing on large hives (e.g. SOFTWARE hive with 25k+ bins)
    let low = 0;
    let high = this.binMap.length - 1;

    while (low <= high) {
      const mid = (low + high) >>> 1; // Unsigned right shift
      const bin = this.binMap[mid];
      
      if (cellIndex >= bin.logicalStart && cellIndex < bin.logicalStart + bin.size) {
         const offset = bin.physicalOffset + 0x20 + (cellIndex - bin.logicalStart);
         return offset < this.data.length ? offset : null;
      }
      
      if (cellIndex < bin.logicalStart) {
        high = mid - 1;
      } else {
        low = mid + 1;
      }
    }
    return null;
  }

  // v3.1: Build a set of all offsets reachable from the Root Key.
  // Any KeyNode (nk) NOT in this set is likely an Unlinked DKOM artifact.
  public buildReachabilityMap(): Set<number> {
    const reachable = new Set<number>();
    const rootCellIndex = this.view.getUint32(0x24, true); // Root Cell Index from Base Block
    const rootOffset = this.resolveCellOffset(rootCellIndex);

    if (rootOffset) {
      this.traverseTree(rootOffset, reachable);
    } else {
      // Fallback: If header is corrupt, try first valid NK in first bin
      if(this.binMap.length > 0) {
         const firstBin = this.binMap[0];
         const fallback = firstBin.physicalOffset + 0x24; // Usually first cell
         if (this.view.getUint16(fallback, true) === SIG_NK) {
            this.traverseTree(fallback, reachable);
         }
      }
    }
    return reachable;
  }

  private traverseTree(offset: number, visited: Set<number>, depth = 0) {
    if (visited.has(offset) || depth > 256) return;
    visited.add(offset);

    // Ensure it's a Key Node
    if (this.view.getUint16(offset, true) !== SIG_NK) return;

    // Get Subkey List Index (0x1C) and Count (0x14)
    const subkeyCount = this.view.getUint32(offset + 0x14, true);
    const subkeyListIndex = this.view.getUint32(offset + 0x1C, true);

    // Safety Brake: Ignore massive subkey counts which are likely corruption
    if (subkeyCount > 0 && subkeyCount < 0x100000 && subkeyListIndex !== 0xFFFFFFFF) {
      const listOffset = this.resolveCellOffset(subkeyListIndex);
      if (listOffset) {
        this.traverseSubkeyList(listOffset, subkeyCount, visited, depth + 1);
      }
    }
  }

  private traverseSubkeyList(listOffset: number, count: number, visited: Set<number>, depth: number) {
    // FIX: Cycle detection for Lists. 
    // Corrupted hives often have lists pointing to themselves.
    if (visited.has(listOffset)) return; 
    visited.add(listOffset);

    // Basic List Parsing (li, ri, lf, lh)
    // Signature at offset 0
    const sig = this.view.getUint16(listOffset, true);
    const countInList = this.view.getUint16(listOffset + 0x02, true); // Number of elements in this list

    // Safety Brake: Cap list iteration to prevent infinite loops on garbage
    if (countInList > 0x10000) return;

    // li (0x696C) or ri (0x6972) -> Index of other lists
    if (sig === 0x696C || sig === 0x6972) {
       for(let i=0; i<countInList; i++) {
          const nextListIndex = this.view.getUint32(listOffset + 0x04 + (i * 4), true);
          const nextOffset = this.resolveCellOffset(nextListIndex);
          if (nextOffset) this.traverseSubkeyList(nextOffset, count, visited, depth); // Recurse
       }
    }
    // lf (0x666C) or lh (0x686C) -> Actual Key Indexes (Hash Leaf / Fast Leaf)
    else if (sig === 0x666C || sig === 0x686C) {
       for(let i=0; i<countInList; i++) {
          const keyIndex = this.view.getUint32(listOffset + 0x04 + (i * 8), true); // Offset depends on hash/no-hash, usually 4 bytes offset, 4 bytes hash
          const keyOffset = this.resolveCellOffset(keyIndex);
          if (keyOffset) {
             this.traverseTree(keyOffset, visited, depth);
          }
       }
    }
  }

  public readNodeName(offset: number): string {
    if (offset + 0x50 > this.data.length) return "ERR_BOUNDS";
    
    const flags = this.view.getUint16(offset + 0x02, true);
    const nameLen = this.view.getUint16(offset + 0x48, true);
    const nameOffset = offset + 0x4C;

    if (nameOffset + nameLen > this.data.length) return "ERR_LEN";

    const isCompressed = (flags & 0x0020) !== 0; // ASCII

    let name = "";
    if (isCompressed) {
      for (let i = 0; i < nameLen; i++) {
        const charCode = this.data[nameOffset + i];
        name += (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.';
      }
    } else {
      // UTF-16LE
      for (let i = 0; i < nameLen; i++) {
        const charCode = this.data[nameOffset + i];
        if (charCode !== 0) {
          name += (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.';
        }
      }
    }
    return name;
  }

  public resolvePath(startOffset: number, maxDepth: number = 10): { path: string, steps: string[] } {
    let currentOffset = startOffset;
    let pathParts: string[] = [];
    let steps: string[] = [];
    let depth = 0;

    const initialName = this.readNodeName(currentOffset);
    pathParts.unshift(initialName);

    while (depth < maxDepth) {
      const parentCID = this.view.getInt32(currentOffset + 0x10, true); 
      
      if (parentCID === -1 || parentCID === 0) {
        steps.push(`Root reached or detached at depth ${depth}`);
        break;
      }

      const parentOffset = this.resolveCellOffset(parentCID);
      
      if (!parentOffset) {
        steps.push(`Could not resolve parent CID: ${parentCID}`);
        break;
      }

      const sig = this.view.getUint16(parentOffset, true);
      if (sig !== SIG_NK) {
        steps.push(`Parent at ${parentOffset.toString(16)} is not a Key Node (sig: ${sig.toString(16)})`);
        break;
      }

      const parentName = this.readNodeName(parentOffset);
      pathParts.unshift(parentName);
      steps.push(`Resolved parent '${parentName}' at offset 0x${parentOffset.toString(16)}`);

      currentOffset = parentOffset;
      depth++;
    }

    return {
      path: pathParts.join('\\'),
      steps: steps
    };
  }

  public analyzeHeuristics(offset: number): string[] {
    const warnings: string[] = [];
    const flags = this.view.getUint16(offset + 0x02, true);
    const parentCID = this.view.getInt32(offset + 0x10, true);
    const skCID = this.view.getInt32(offset + 0x20, true);
    const timestamp = this.view.getBigUint64(offset + 0x04, true);

    if ((flags & 0x10) || (flags & 0x20)) {
      warnings.push("Virtualization Flags Detected (0x10/0x20)");
    }
    if (parentCID === -1 && (flags & 0x04) === 0) { 
      warnings.push("Orphaned Node (Possible Ghost Key)");
    }

    if (skCID !== -1) {
      const skOffset = this.resolveCellOffset(skCID);
      if (skOffset) {
         const skSig = this.view.getUint16(skOffset, true);
         if (skSig === 0x6B73) { 
            const sdLen = this.view.getUint32(skOffset + 0x10, true); 
            if (sdLen < 20) warnings.push("Suspiciously Small Security Descriptor (Possible Null DACL)");
         }
      }
    }

    const year = new Date(Number(timestamp / 10000n - 11644473600000n)).getFullYear();
    if (year < 1990 || year > 2035) {
      warnings.push("Invalid Timestamp (Composite Merge Artifact or Corruption)");
    }

    return warnings;
  }
}
