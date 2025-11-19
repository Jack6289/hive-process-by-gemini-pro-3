
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
  
  const logVersion = logView.getUint32(0x14, true); // Sequence number from 0x14 (secondary) or 0x4 (primary)

  // Iterate through the log file looking for 'hbin' records.
  let cursor = BASE_BLOCK_SIZE; // Skip log header (4096 bytes)

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
        expansion += (newSize - mainHive.length);
      }

      // Apply the Patch
      // Log files store dirty pages exactly as they should appear in the main hive
      const patchData = logData.slice(cursor, cursor + size);
      buffer.set(patchData, targetOffset);
      
      patches++;
      cursor += size;
    } else {
      // Skip padding / alignment
      cursor += 512; 
    }
  }

  return {
    patchedBuffer: buffer,
    patchesApplied: patches,
    bytesExpanded: expansion,
    logVersion: logVersion
  };
};

/**
 * Handles multiple log files (e.g. NTUSER.DAT.LOG1 and LOG2).
 * Sorts them by sequence number and applies them in order.
 */
export const reconcileMultipleLogs = (mainHive: Uint8Array, logs: Uint8Array[]): ReconcileResult => {
  // 1. Map logs to include their sequence number
  const mappedLogs = logs.map(log => ({
    data: log,
    seq: getLogSequenceNumber(log)
  }));

  // 2. Sort ascending (Oldest -> Newest)
  // This ensures we replay history correctly
  mappedLogs.sort((a, b) => a.seq - b.seq);

  let currentBuffer = mainHive;
  let totalPatches = 0;
  let totalExpansion = 0;
  let finalVersion = 0;

  // 3. Apply sequentially
  for (const logEntry of mappedLogs) {
    if (logEntry.seq === 0) continue; // Skip invalid logs

    const result = reconcileLog(currentBuffer, logEntry.data);
    currentBuffer = result.patchedBuffer;
    totalPatches += result.patchesApplied;
    totalExpansion += result.bytesExpanded;
    finalVersion = result.logVersion;
  }

  return {
    patchedBuffer: currentBuffer,
    patchesApplied: totalPatches,
    bytesExpanded: totalExpansion,
    logVersion: finalVersion
  };
};
