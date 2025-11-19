
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
 * Extracts the primary sequence number from a Registry Hive/Log header.
 * Offset 0x04 (4 bytes).
 */
export const getLogSequenceNumber = (logData: Uint8Array): number => {
  if (logData.length < 0x10) return 0;
  const view = new DataView(logData.buffer, logData.byteOffset, logData.byteLength);
  // Check signature 'regf'
  if (view.getUint32(0, true) !== 0x66676572) return 0;
  return view.getUint32(0x04, true);
};

/**
 * Replays a Transaction Log (.LOG1/2) onto the Main Hive File.
 */
export const reconcileLog = (mainHive: Uint8Array, logData: Uint8Array): ReconcileResult => {
  // 1. Create a working copy of the main hive
  let buffer = new Uint8Array(mainHive);
  let patches = 0;
  
  // Track the furthest byte that contains valid data.
  // We initialize it to the original size. 
  // If the log adds data beyond the end, this will increase.
  let maxWriteOffset = mainHive.length;

  const logView = new DataView(logData.buffer, logData.byteOffset, logData.byteLength);
  const logLen = logData.length;

  // Check Log Header (REGF)
  const sig = logView.getUint32(0, true);
  if (sig !== 0x66676572) { // 'regf'
    throw new Error("Invalid Log File Signature");
  }
  
  const logVersion = logView.getUint32(0x14, true); 

  // Iterate through the log file looking for 'hbin' records.
  let cursor = BASE_BLOCK_SIZE; // Skip log header (4096 bytes)

  while (cursor < logLen - 32) {
    const chunkSig = logView.getUint32(cursor, true);
    
    if (chunkSig === SIG_HBIN) {
      const offsetRelative = logView.getUint32(cursor + 0x04, true);
      const size = logView.getUint32(cursor + 0x08, true);
      
      if (size === 0) break; // Safety

      // Calculate target physical offset in Main Hive
      const targetOffset = BASE_BLOCK_SIZE + offsetRelative;
      const endOffset = targetOffset + size;

      // Update the valid data boundary
      if (endOffset > maxWriteOffset) {
        maxWriteOffset = endOffset;
      }

      // Expand buffer if needed to accommodate this patch
      if (endOffset > buffer.length) {
        // Grow strategy: Max of needed size OR current + 4MB (to minimize re-allocations)
        // We will TRIM the excess zeros at the end function.
        const newSize = Math.max(endOffset, buffer.length + (4 * 1024 * 1024)); 
        const newBuffer = new Uint8Array(newSize);
        newBuffer.set(buffer);
        buffer = newBuffer;
      }

      // Apply the Patch
      const patchData = logData.slice(cursor, cursor + size);
      buffer.set(patchData, targetOffset);
      
      patches++;
      cursor += size;
    } else {
      // Skip padding / alignment
      cursor += 512; 
    }
  }

  // FINAL TRIM: Cut off the excess pre-allocated zeros.
  // Windows Registry files must be aligned to 4KB (0x1000).
  // If we leave trailing zeros beyond the last valid hbin, Regedit stops parsing early.
  const remainder = maxWriteOffset % 4096;
  const padding = remainder === 0 ? 0 : 4096 - remainder;
  const finalSize = maxWriteOffset + padding;

  let finalBuffer = buffer;
  if (buffer.length !== finalSize) {
      // If our working buffer is different from the calculated final size, resize it.
      if (finalSize > buffer.length) {
          // Grow (Rare case if padding pushes over boundary)
          const tmp = new Uint8Array(finalSize);
          tmp.set(buffer);
          finalBuffer = tmp;
      } else {
          // Shrink (Common case: removing the 4MB speculative growth)
          finalBuffer = buffer.slice(0, finalSize);
      }
  }

  const expansion = finalBuffer.length - mainHive.length;

  return {
    patchedBuffer: finalBuffer,
    patchesApplied: patches,
    bytesExpanded: expansion > 0 ? expansion : 0,
    logVersion: logVersion
  };
};

/**
 * Handles multiple log files (e.g. NTUSER.DAT.LOG1 and LOG2).
 * Sorts them by sequence number and applies them in order.
 */
export const reconcileMultipleLogs = (mainHive: Uint8Array, logs: Uint8Array[]): ReconcileResult => {
  const mappedLogs = logs.map(log => ({
    data: log,
    seq: getLogSequenceNumber(log)
  }));

  // Sort ascending (Oldest -> Newest)
  mappedLogs.sort((a, b) => a.seq - b.seq);

  let currentBuffer = mainHive;
  let totalPatches = 0;
  let totalExpansion = 0;
  let finalVersion = 0;

  for (const logEntry of mappedLogs) {
    if (logEntry.seq === 0) continue; 

    const result = reconcileLog(currentBuffer, logEntry.data);
    currentBuffer = result.patchedBuffer;
    totalPatches += result.patchesApplied;
    // Precise expansion calculation is done at the very end
    finalVersion = result.logVersion;
  }
  
  // Precise expansion calculation
  totalExpansion = currentBuffer.length - mainHive.length;

  return {
    patchedBuffer: currentBuffer,
    patchesApplied: totalPatches,
    bytesExpanded: totalExpansion > 0 ? totalExpansion : 0,
    logVersion: finalVersion
  };
};
