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
        // If not hbin, maybe we just skip? In corrupted files, this might fail.
        // For now, we assume standard structure or stop.
        break; 
      }

      const offsetRelative = this.view.getUint32(cursor + 0x04, true);
      const size = this.view.getUint32(cursor + 0x08, true);

      this.binMap.push({
        logicalStart: offsetRelative,
        physicalOffset: cursor,
        size: size
      });

      if (size === 0) break; // Prevent infinite loop on corruption
      cursor += size;
    }
  }

  public resolveCellOffset(cellIndex: number): number | null {
    // Find the bin containing this cell index
    // Cell Index is relative to the start of the first bin's data area
    const bin = this.binMap.find(b => cellIndex >= b.logicalStart && cellIndex < b.logicalStart + b.size);
    
    if (!bin) return null;

    // Physical = BinStart + Header(0x20) + (CellIndex - BinLogicalStart)
    // Note: size includes header. logicalStart is the offset of this bin relative to registry start?
    // Actually, cell index is usually just offset relative to start of hive bins (0x1000).
    // But in multi-bin files, the bins might not be contiguous in memory if mapped, but in file they are.
    // The standard calc:
    const offset = bin.physicalOffset + 0x20 + (cellIndex - bin.logicalStart);
    
    // Bounds check
    if (offset >= this.data.length) return null;
    return offset;
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
      // We take bytes. If standard unicode, typical english is Byte, 00, Byte, 00.
      for (let i = 0; i < nameLen; i++) {
        const charCode = this.data[nameOffset + i];
        // Simple heuristic: if 0, skip (it's likely the high byte of a latin char)
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

    // Get name of current node
    const initialName = this.readNodeName(currentOffset);
    pathParts.unshift(initialName);

    while (depth < maxDepth) {
      // Get Parent Cell Index at 0x10
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

      // Check if parent is a valid NK
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

    // 1. Virtualization
    if ((flags & 0x10) || (flags & 0x20)) {
      warnings.push("Virtualization Flags Detected (0x10/0x20)");
    }
    if (parentCID === -1 && (flags & 0x04) === 0) { // Not root but no parent
      warnings.push("Orphaned Node (Possible Ghost Key)");
    }

    // 2. ACL / Hidden
    if (skCID !== -1) {
      const skOffset = this.resolveCellOffset(skCID);
      if (skOffset) {
         const skSig = this.view.getUint16(skOffset, true);
         if (skSig === 0x6B73) { // sk
            // Security descriptor check
            const sdLen = this.view.getUint32(skOffset + 0x10, true); // Descriptor Length
            if (sdLen < 20) warnings.push("Suspiciously Small Security Descriptor (Possible Null DACL)");
         }
      }
    }

    // 3. Timestamp Anomalies
    const year = new Date(Number(timestamp / 10000n - 11644473600000n)).getFullYear();
    if (year < 1990 || year > 2035) {
      warnings.push("Invalid Timestamp (Composite Merge Artifact or Corruption)");
    }

    // 4. Corruption (Name)
    const name = this.readNodeName(offset);
    if (name.includes("ERR") || name.length === 0) {
      warnings.push("Name Parsing Error (Corruption)");
    }

    return warnings;
  }
}