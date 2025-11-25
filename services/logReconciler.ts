
const SIG_HBIN = 0x6E696268; // 'hbin'
const BASE_BLOCK_SIZE = 0x1000; // 4096 bytes header

export interface ReconcileResult {
  patchedBuffer: Uint8Array;
  patchesApplied: number;
  bytesExpanded: number;
  finalSequence: number;
  logsProcessed: number;
}

export const getLogSequenceNumber = (logData: Uint8Array): number => {
  if (logData.length < 0x10) return 0;
  const view = new DataView(logData.buffer, logData.byteOffset, logData.byteLength);
  if (view.getUint32(0, true) !== 0x66676572) return 0; // 'regf'
  return view.getUint32(0x04, true);
};

/**
 * Robust Log Replayer.
 * Treats the log as a stream of "Dirty Pages" to be stamped onto the main hive.
 * This mimics the kernel's paging mechanism rather than logical parsing.
 * 
 * FIXES CRASHES: Enforces 4KB page alignment to prevent structural corruption.
 */
export const reconcileLog = (mainHive: Uint8Array, logData: Uint8Array): ReconcileResult => {
  let buffer = new Uint8Array(mainHive);
  let patches = 0;
  const logView = new DataView(logData.buffer, logData.byteOffset, logData.byteLength);
  const logLen = logData.length;

  // 1. Validate Header
  if (logView.getUint32(0, true) !== 0x66676572) {
    throw new Error("Invalid Log Signature");
  }
  
  // Offset 0x04 is the Sequence Number (not version)
  const sequence = logView.getUint32(0x04, true);

  // 2. Iterate Log Entries
  // Valid logs are a sequence of Hive Bins (hbin) starting at 0x1000.
  let cursor = BASE_BLOCK_SIZE; 

  while (cursor < logLen - 32) {
    const sig = logView.getUint32(cursor, true);
    
    if (sig === SIG_HBIN) {
      // Read the Dirty Page info
      const offsetRelative = logView.getUint32(cursor + 0x04, true); // Relative to start of Hive Data (0x1000)
      const size = logView.getUint32(cursor + 0x08, true); // Size of this dirty block

      // CRITICAL FIX: Page Alignment Enforcement
      // Real hive blocks in logs are ALWAYS page aligned (4096).
      // If we see unaligned sizes, it's likely garbage or partial writes. 
      // Applying these would corrupt the hbin chain and crash Regedit.
      if (size === 0 || size % 4096 !== 0) {
          // console.warn(`Stopping log replay at unaligned block (Potential Corruption). Offset: 0x${cursor.toString(16)}, Size: ${size}`);
          break; 
      }

      const targetPhysicalOffset = BASE_BLOCK_SIZE + offsetRelative;
      const endOffset = targetPhysicalOffset + size;

      // 3. Expand Buffer if needed (Exact Page Alignment)
      if (endOffset > buffer.length) {
        const newSize = endOffset; // Since size is 4KB aligned, newSize will be too.
        const newBuffer = new Uint8Array(newSize);
        newBuffer.set(buffer);
        buffer = newBuffer;
      }

      // 4. Stamp the Data
      // We copy specific bytes from Log -> Main
      const dirtyData = logData.slice(cursor, cursor + size);
      buffer.set(dirtyData, targetPhysicalOffset);

      patches++;
      cursor += size;
    } else {
      // Garbage Handling:
      // If we hit non-hbin data, scan ahead to find the next valid bin.
      // This handles cases where the log has "holes" or sector padding.
      let foundNext = false;
      // Scan up to 4KB ahead looking for SIG_HBIN
      for(let scan = cursor + 4; scan < Math.min(cursor + 4096, logLen - 4); scan += 4) {
          if (logView.getUint32(scan, true) === SIG_HBIN) {
              cursor = scan;
              foundNext = true;
              break;
          }
      }
      
      if (!foundNext) {
          // If we can't find a valid bin nearby, assume end of valid log data.
          break; 
      }
    }
  }

  // 5. Final Sanity Check: Ensure File Size is Page Aligned
  if (buffer.length % 4096 !== 0) {
      const paddingNeeded = 4096 - (buffer.length % 4096);
      const paddedBuffer = new Uint8Array(buffer.length + paddingNeeded);
      paddedBuffer.set(buffer);
      buffer = paddedBuffer;
  }

  const expansion = buffer.length - mainHive.length;

  return {
    patchedBuffer: buffer,
    patchesApplied: patches,
    bytesExpanded: expansion > 0 ? expansion : 0,
    finalSequence: sequence,
    logsProcessed: 1
  };
};

export const reconcileMultipleLogs = (mainHive: Uint8Array, logs: Uint8Array[]): ReconcileResult => {
  const mappedLogs = logs.map(log => ({
    data: log,
    seq: getLogSequenceNumber(log)
  }));

  // Sort Oldest -> Newest
  mappedLogs.sort((a, b) => a.seq - b.seq);

  let currentBuffer = mainHive;
  let totalPatches = 0;
  let lastSeq = 0;
  let processedCount = 0;

  for (const logEntry of mappedLogs) {
    if (logEntry.seq === 0) continue; 
    const result = reconcileLog(currentBuffer, logEntry.data);
    currentBuffer = result.patchedBuffer;
    totalPatches += result.patchesApplied;
    lastSeq = result.finalSequence;
    processedCount++;
  }

  const totalExpansion = currentBuffer.length - mainHive.length;

  return {
    patchedBuffer: currentBuffer,
    patchesApplied: totalPatches,
    bytesExpanded: totalExpansion > 0 ? totalExpansion : 0,
    finalSequence: lastSeq,
    logsProcessed: processedCount
  };
};
