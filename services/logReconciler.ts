
const SIG_HBIN = 0x6E696268; // 'hbin'
const BIN_HEADER_SIZE = 0x20;
const BASE_BLOCK_SIZE = 0x1000;

export interface ReconcileResult {
  patchedBuffer: Uint8Array;
  patchesApplied: number;
  bytesExpanded: number;
  logVersion: number;
}

/**
 * Replays a Transaction Log (.LOG1/2) onto the Main Hive File.
 * This mimics the Windows Kernel's behavior of merging dirty pages into memory.
 */
export const reconcileLog = (mainHive: Uint8Array, logData: Uint8Array): ReconcileResult => {
  // 1. Create a working copy of the main hive (we might need to resize it)
  let buffer = new Uint8Array(mainHive);
  let patches = 0;
  let expansion = 0;

  const logView = new DataView(logData.buffer, logData.byteOffset, logData.byteLength);
  const logLen = logData.length;

  // Check Log Header (REGF)
  const sig = logView.getUint32(0, true);
  if (sig !== 0x66676572) { // 'regf'
    throw new Error("Invalid Log File Signature");
  }
  
  const logVersion = logView.getUint32(0x14, true); // Sequence number

  // Iterate through the log file looking for 'hbin' records.
  // Log files usually contain a Base Block (4k) followed by hbin records.
  // The hbin records in the log contain the *new content* for specific offsets in the main hive.
  
  let cursor = BASE_BLOCK_SIZE; // Skip log header

  while (cursor < logLen - 32) {
    const chunkSig = logView.getUint32(cursor, true);
    
    if (chunkSig === SIG_HBIN) {
      const offsetRelative = logView.getUint32(cursor + 0x04, true);
      const size = logView.getUint32(cursor + 0x08, true);
      
      if (size === 0) break; // Safety

      // Calculate target physical offset in Main Hive
      // Main Hive Data starts at 0x1000. OffsetRelative is from start of Data.
      const targetOffset = BASE_BLOCK_SIZE + offsetRelative;

      // Check if we need to expand the main hive buffer
      const endOffset = targetOffset + size;
      if (endOffset > buffer.length) {
        const newSize = Math.max(endOffset, buffer.length + (4 * 1024 * 1024)); // Grow by 4MB chunks
        const newBuffer = new Uint8Array(newSize);
        newBuffer.set(buffer);
        buffer = newBuffer;
        expansion = newSize - mainHive.length;
      }

      // Apply the Patch
      const patchData = logData.slice(cursor, cursor + size);
      buffer.set(patchData, targetOffset);
      
      patches++;
      cursor += size;
    } else {
      // If not an hbin, it might be padding or end of data. 
      // In strict parsing we check structure, heuristic just skips 512 bytes?
      // Since registry blocks are aligned, we step forward carefully.
      cursor += 512; 
    }
  }

  // Trim buffer to actual used size if we expanded too much? 
  // For forensics, keeping slack is fine.

  return {
    patchedBuffer: buffer,
    patchesApplied: patches,
    bytesExpanded: expansion,
    logVersion: logVersion
  };
};
