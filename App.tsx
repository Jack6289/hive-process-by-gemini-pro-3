
import React, { useState, useRef, useCallback, useEffect } from 'react';
import HexViewer from './components/HexViewer';
import AnalysisPanel from './components/AnalysisPanel';
import { scanHiveForAnomalies, searchHive } from './services/hiveScanner';
import { reconcileMultipleLogs, ReconcileResult } from './services/logReconciler';
import { ScanFinding } from './types';

// --- CRITICAL KERNEL-SAFE UTILITIES (v7.1) ---

// 1. Kernel-Safe Neuter with DIFF LOGGING
const neuterKeyNode = (buffer: Uint8Array, offset: number, providedView?: DataView): string[] => {
    const view = providedView || new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const changes: string[] = [];

    // Helper to log changes
    const logChange = (field: string, oldVal: any, newVal: any) => {
        changes.push(`[NEUTER] Offset 0x${offset.toString(16)}: ${field} ${oldVal} -> ${newVal}`);
    };

    // A. Update Timestamp
    const oldTime = view.getBigUint64(offset + 0x04, true);
    const nowMs = BigInt(Date.now());
    const fileTime = (nowMs + 11644473600000n) * 10000n; 
    view.setBigUint64(offset + 0x04, fileTime, true);
    // logChange("Timestamp", oldTime, fileTime);

    // B. Clear Subkeys
    const oldSubCount = view.getUint32(offset + 0x14, true);
    view.setUint32(offset + 0x14, 0, true); 
    if(oldSubCount !== 0) logChange("SubkeyCount", oldSubCount, 0);

    view.setUint32(offset + 0x18, 0, true); 
    view.setInt32(offset + 0x1C, -1, true); 
    view.setInt32(offset + 0x20, -1, true); 

    // C. Clear Values
    const oldValCount = view.getUint32(offset + 0x24, true);
    view.setUint32(offset + 0x24, 0, true); 
    if(oldValCount !== 0) logChange("ValueCount", oldValCount, 0);

    view.setInt32(offset + 0x28, -1, true); 

    // E. v6.1 CRITICAL FIX: Zero out Max Length Statistics
    view.setUint32(offset + 0x34, 0, true); 
    view.setUint32(offset + 0x38, 0, true); 
    view.setUint32(offset + 0x3C, 0, true); 
    view.setUint32(offset + 0x40, 0, true); 
    
    return changes;
};

// 2. Fix Hive Header & Sync Sequences & LENGTH (v7.0 STRICT)
const fixHiveHeader = (buffer: Uint8Array): string[] => {
    const logs: string[] = [];
    if (buffer.length < 0x1000) return ["ERROR: File too small"];
    
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    
    if (view.getUint32(0, true) !== 0x66676572) return ["ERROR: Invalid Signature"];

    // A. Update Base Block Timestamp
    const nowMs = BigInt(Date.now());
    const fileTime = (nowMs + 11644473600000n) * 10000n; 
    view.setBigUint64(0x0C, fileTime, true);

    // B. Sync Sequence Numbers
    const seq = view.getUint32(0x04, true);
    view.setUint32(0x04, seq + 1, true); 
    view.setUint32(0x08, seq + 1, true); 
    logs.push(`[HEADER] Sequence bumped to ${seq + 1}`);

    // C. v6.4 FIX: Update File Length Header (Offset 0x28)
    const dataLength = buffer.length - 0x1000;
    const oldLen = view.getUint32(0x28, true);
    view.setUint32(0x28, dataLength, true);
    if(oldLen !== dataLength) logs.push(`[HEADER] Length corrected: ${oldLen} -> ${dataLength}`);

    // D. Recalculate XOR Checksum
    // v7.0: ZERO OUT CHECKSUM FIELD FIRST
    view.setUint32(0x1FC, 0, true); 
    
    let xorSum = 0;
    for (let i = 0; i < 0x1FC; i += 4) {
        xorSum ^= view.getUint32(i, true);
    }
    
    view.setUint32(0x1FC, xorSum, true);
    // Fix: Display as unsigned hex
    logs.push(`[HEADER] New Checksum: 0x${(xorSum >>> 0).toString(16).toUpperCase()}`);
    
    return logs;
};

// --- VANILLA DOM OVERLAY HELPERS ---
const OVERLAY_ID = 'hivemind-progress-overlay';

const injectOverlay = () => {
    const existing = document.getElementById(OVERLAY_ID);
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    overlay.style.position = 'fixed';
    overlay.style.inset = '0';
    overlay.style.zIndex = '10000';
    overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.9)';
    overlay.style.backdropFilter = 'blur(4px)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.transition = 'opacity 0.2s ease-in';
    
    overlay.innerHTML = `
      <div style="background-color: #111827; border: 1px solid #374151; padding: 24px; border-radius: 12px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); width: 384px;">
         <h3 style="color: #22d3ee; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
            <svg class="animate-spin" style="height: 20px; width: 20px; color: #06b6d4;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle style="opacity: 0.25;" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path style="opacity: 0.75;" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span id="${OVERLAY_ID}-title">Starting...</span>
         </h3>
         <div style="width: 100%; background-color: #1f2937; border-radius: 9999px; height: 10px; margin-bottom: 8px; overflow: hidden;">
            <div id="${OVERLAY_ID}-bar" style="background-color: #06b6d4; height: 100%; width: 0%; transition: width 0.1s linear;"></div>
         </div>
         <div style="display: flex; justify-content: space-between; font-size: 12px; font-family: monospace; color: #9ca3af;">
            <span id="${OVERLAY_ID}-count">Initializing...</span>
            <span id="${OVERLAY_ID}-status">Processing</span>
         </div>
      </div>
    `;
    
    document.body.appendChild(overlay);
};

const updateOverlay = (percent: number, countStr: string, statusStr?: string) => {
    const bar = document.getElementById(`${OVERLAY_ID}-bar`);
    const count = document.getElementById(`${OVERLAY_ID}-count`);
    const status = document.getElementById(`${OVERLAY_ID}-status`);
    const title = document.getElementById(`${OVERLAY_ID}-title`);

    if (bar) bar.style.width = `${percent}%`;
    if (count) count.innerText = countStr;
    if (status && statusStr) status.innerText = statusStr;
    if (title && percent >= 100) title.innerText = "Finalizing Structure...";
};

const removeOverlay = () => {
    const overlay = document.getElementById(OVERLAY_ID);
    if (overlay) {
        overlay.style.opacity = '0';
        setTimeout(() => overlay.remove(), 200);
    }
};

// --- CUSTOM CONFIRMATION MODAL ---
const ConfirmationModal = ({ count, onConfirm, onCancel }: { count: number, onConfirm: () => void, onCancel: () => void }) => {
  const isMassDestruction = count > 100;

  return (
    <div className="fixed inset-0 z-[10001] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className={`bg-gray-900 border rounded-xl p-6 max-w-md w-full shadow-2xl transform transition-all scale-100 animate-in fade-in zoom-in duration-200 ${isMassDestruction ? 'border-red-600 shadow-red-900/20' : 'border-gray-800'}`}>
        <h3 className={`text-xl font-bold mb-4 flex items-center gap-2 ${isMassDestruction ? 'text-red-500' : 'text-cyan-500'}`}>
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          {isMassDestruction ? 'CRITICAL SAFETY WARNING' : 'Confirm Action'}
        </h3>
        <p className="text-gray-300 mb-6 text-sm leading-relaxed">
          You are about to scan <strong className="text-white">{count}</strong> candidates for safe neutralization. 
          <br/><br/>
          {isMassDestruction && (
              <div className="bg-red-950/50 border border-red-900 p-3 rounded mb-4 text-red-200 text-xs">
                  <strong>SMART TARGETING ENABLED:</strong> 
                  <br/>
                  Batch operation will strictly enforce SYSTEM SAFETY:
                  <ul className="list-disc pl-4 mt-1 space-y-1">
                      <li>Deleting <strong>Search Results</strong> is allowed (User Intent).</li>
                      <li>Deleting <strong>High-Confidence Rootkits</strong> is allowed.</li>
                      <li><strong>CRITICAL BOOT KEYS</strong> are <span className="text-red-400 font-bold">LOCKED</span> (Skipped).</li>
                      <li>Keys with {'>'}20 subkeys are <span className="text-red-400 font-bold">SKIPPED</span> (Too Risky).</li>
                  </ul>
              </div>
          )}
          <span className="text-yellow-400 font-bold text-xs uppercase block mb-2">⚠ Boot Safety Warning</span>
          When replacing the hive file in Windows/System32/config, you <strong className="text-white">MUST DELETE or RENAME</strong> the associated <code>.LOG1</code> and <code>.LOG2</code> files.
        </p>
        <div className="flex gap-3 justify-end">
          <button onClick={onCancel} className="px-4 py-2 rounded bg-gray-800 text-gray-300 hover:bg-gray-700 text-xs font-bold uppercase tracking-wide transition-colors">
            Cancel
          </button>
          <button onClick={onConfirm} className={`px-4 py-2 rounded text-white text-xs font-bold uppercase tracking-wide shadow-lg transition-colors ${isMassDestruction ? 'bg-red-700 hover:bg-red-800 shadow-red-900/50' : 'bg-cyan-700 hover:bg-cyan-800 shadow-cyan-900/50'}`}>
            {isMassDestruction ? 'PROCEED SAFELY' : 'Yes, Neuter All'}
          </button>
        </div>
      </div>
    </div>
  );
};

const App: React.FC = () => {
  const [fileData, setFileData] = useState<Uint8Array | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [selectedBytes, setSelectedBytes] = useState<Uint8Array | null>(null);
  const [selectionOffset, setSelectionOffset] = useState<number>(0);
  const [scanResults, setScanResults] = useState<ScanFinding[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [reconcileStats, setReconcileStats] = useState<ReconcileResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  
  // Confirmation Modal State
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [batchNeuterCount, setBatchNeuterCount] = useState(0);
  
  const fileDataRef = useRef<Uint8Array | null>(null);
  const scanResultsRef = useRef<ScanFinding[]>([]);

  useEffect(() => { fileDataRef.current = fileData; }, [fileData]);
  useEffect(() => { scanResultsRef.current = scanResults; }, [scanResults]);

  const [actionStatus, setActionStatus] = useState<'idle' | 'starting' | 'processing' | 'completed'>('idle');
  const [aiMode, setAiMode] = useState<string>('ROOTKIT_ENGINE_READY');
  const [selectionRange, setSelectionRange] = useState<{start: number, end: number} | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const logInputRef = useRef<HTMLInputElement>(null);

  const addLog = useCallback((msg: string) => {
    const time = new Date().toLocaleTimeString();
    setLogs(prev => [`[${time}] ${msg}`, ...prev]);
  }, []);

  const onSelectionChange = useCallback((start: number, end: number, customBuffer?: Uint8Array) => {
    const buffer = customBuffer || fileData;
    if (!buffer) return;
    const maxLen = 8192; 
    const len = end - start + 1;
    let actualEnd = end;
    if (len > maxLen) {
        actualEnd = start + maxLen - 1;
    }

    const slice = buffer.slice(start, actualEnd + 1);
    setSelectedBytes(slice);
    setSelectionOffset(start);
    setSelectionRange({ start, end: actualEnd });
  }, [fileData]);

  // v7.3: Native File System Access API Support
  const handleNativeFileOpen = async () => {
    if ('showOpenFilePicker' in window) {
        try {
            // @ts-ignore - TS might not have types for this yet
            const [fileHandle] = await window.showOpenFilePicker({
                types: [{
                    description: 'Windows Registry Hives',
                    accept: {
                        'application/octet-stream': ['.dat', '.', ''] 
                    }
                }],
                multiple: false
            });
            
            const file = await fileHandle.getFile();
            
            // SECURITY CHECK: Locked files often report 0 bytes
            if (file.size === 0) {
                alert("ACCESS DENIED: The selected file is currently LOCKED by the operating system.\n\nRegistry hives (like SYSTEM, SOFTWARE) cannot be edited while Windows is running.\n\nPlease copy the file to a different location (e.g., Desktop) or use 'reg save' command before analyzing.");
                return;
            }

            const buffer = await file.arrayBuffer();
            const uint8 = new Uint8Array(buffer.slice(0, 512 * 1024 * 1024)); // 512MB limit
            
            setFileData(uint8);
            setFileName(file.name);
            setScanResults([]); 
            setLogs([]);
            addLog(`File Opened (Native Auth): ${file.name} (${(uint8.length / 1024 / 1024).toFixed(2)} MB)`);

        } catch (err) {
            // User cancelled or error
            if ((err as Error).name !== 'AbortError') {
                console.error("FS API Error:", err);
                // Fallback to old input
                fileInputRef.current?.click();
            }
        }
    } else {
        // Fallback for browsers without API support
        fileInputRef.current?.click();
    }
  };

  // Fallback Legacy Upload
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      if (event.target?.result) {
        const buffer = event.target.result as ArrayBuffer;
        const uint8 = new Uint8Array(buffer.slice(0, 512 * 1024 * 1024));
        setFileData(uint8);
        setFileName(file.name);
        setScanResults([]); 
        setLogs([]);
        addLog("File Loaded: " + file.name + " (" + (uint8.length / 1024 / 1024).toFixed(2) + " MB)");
      }
    };
    reader.readAsArrayBuffer(file);
  };
  
  const handleLogUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!fileData || !e.target.files?.length) return;
    const files: File[] = Array.from(e.target.files);
    
    const readers = files.map((file: File) => new Promise<Uint8Array>((resolve) => {
      const reader = new FileReader();
      reader.onload = (evt) => {
        if (evt.target?.result) {
          resolve(new Uint8Array(evt.target.result as ArrayBuffer));
        }
      };
      reader.readAsArrayBuffer(file);
    }));

    Promise.all(readers).then(logs => {
      try {
        const result = reconcileMultipleLogs(fileData, logs);
        setFileData(result.patchedBuffer);
        setReconcileStats(result);
        setScanResults([]); 
        addLog(`Logs Merged: ${result.logsProcessed}, Seq: ${result.finalSequence}`);
        alert(`Logs Applied Successfully.\n\nPatches: ${result.patchesApplied}\nExpanded: ${result.bytesExpanded} bytes\nFiles Merged: ${result.logsProcessed}\nFinal Seq: ${result.finalSequence}\n\nPlease re-scan to find new or modified keys.`);
      } catch (err) {
        alert("Log Replay Failed: " + err);
      }
    });
  };

  const performSearch = useCallback(() => {
      if (!fileData || !searchQuery) return;
      const findings = searchHive(fileData, searchQuery);
      setScanResults(findings);
      addLog(`Search '${searchQuery}' found ${findings.length} matches`);
      if (findings.length > 0) {
          const f = findings[0];
          onSelectionChange(f.offset, f.offset + f.length - 1);
      } else {
          alert(`No matches found for "${searchQuery}"`);
      }
  }, [fileData, searchQuery, onSelectionChange, addLog]);

  const handleSearchKey = (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') performSearch();
  };

  const performScan = useCallback(() => {
    if (!fileData) return;
    setIsScanning(true);
    addLog("Starting Scan...");
    setTimeout(() => {
      const findings = scanHiveForAnomalies(fileData);
      setScanResults(findings);
      setIsScanning(false);
      addLog(`Scan Complete: ${findings.length} findings`);
      if (findings.length > 0) {
          const f = findings[0];
          onSelectionChange(f.offset, f.offset + f.length - 1);
      }
    }, 100);
  }, [fileData, onSelectionChange, addLog]);

  const handleSelectFinding = useCallback((finding: ScanFinding) => {
    onSelectionChange(finding.offset, finding.offset + finding.length - 1);
  }, [onSelectionChange]);

  const handleContextChange = useCallback((offset: number, len: number) => {
     if (!fileData) return;
     let end = offset + len - 1;
     onSelectionChange(offset, end);
  }, [fileData, onSelectionChange]);

  const handleDeleteKey = useCallback((finding: ScanFinding) => {
    if (!fileData) return;
    const newBuffer = new Uint8Array(fileData); 
    const changes = neuterKeyNode(newBuffer, finding.offset);
    changes.forEach(c => addLog(c));
    
    setFileData(newBuffer);
    setScanResults(prev => prev.map(f => f.id === finding.id ? { ...f, isDeleted: true } : f));
    onSelectionChange(finding.offset, finding.offset + finding.length - 1, newBuffer);
  }, [fileData, onSelectionChange, addLog]);

  const handlePatchBytes = useCallback((offset: number, bytes: Uint8Array) => {
    if (!fileData) return;
    const newBuffer = new Uint8Array(fileData);
    newBuffer.set(bytes, offset);
    setFileData(newBuffer);
    addLog(`Manual Patch at 0x${offset.toString(16)} (${bytes.length} bytes)`);
    onSelectionChange(offset, offset + bytes.length - 1, newBuffer);
  }, [fileData, onSelectionChange, addLog]);

  // --- ROBUST BATCH PROCESSING LOOP (v9.0 SYSINTERNALS SMART) ---
  const startProcessingLoop = (
      sourceData: Uint8Array, 
      sourceResults: ScanFinding[], 
      totalActive: number
  ) => {
       try {
            const newBuffer = new Uint8Array(sourceData);
            const mainView = new DataView(newBuffer.buffer, newBuffer.byteOffset, newBuffer.byteLength);
            const workingScanResults = [...sourceResults];
            
            const CHUNK_SIZE = 50; 
            let processedGlobal = 0;
            let scanIndex = 0;
            let skippedSafety = 0;

            const interval = setInterval(() => {
                let chunkProcessed = 0;
                while (scanIndex < workingScanResults.length && chunkProcessed < CHUNK_SIZE) {
                    const f = workingScanResults[scanIndex];
                    if (f && !f.isDeleted) {
                        // v9.0 SAFETY POLICY UPDATE:
                        // 1. SYSTEM CRITICAL KEYS: LOCKED (Always Skip)
                        // 2. SEARCH MATCHES: ALLOWED (User Intent)
                        // 3. PERSISTENCE (Autoruns): ALLOWED (High Priority)
                        // 4. ROOTKITS: ALLOWED (High Confidence)
                        // 5. MASSIVE TREES (>20 children): SKIPPED (Cascade Risk)
                        
                        const isCritical = f.isSystemCritical;
                        const isMassive = (f.subkeyCount || 0) > 20; 
                        const isIntentional = f.type === 'SEARCH_MATCH';
                        const isPersistence = f.type === 'PERSISTENCE_MECHANISM';
                        const isRootkit = f.confidence >= 0.8 || f.type === 'ROOTKIT_NULL_EMBEDDED' || f.type === 'ROOTKIT_CLASS_INJECTION';

                        const shouldDelete = !isCritical && (
                            (isIntentional || isPersistence) || 
                            (isRootkit && !isMassive)
                        );
                        
                        if (shouldDelete) {
                            try {
                                if (f.offset + 0x50 < newBuffer.length) {
                                    neuterKeyNode(newBuffer, f.offset, mainView);
                                    
                                    // v9.0 ASSOCIATION LOGIC:
                                    // If finding has associated dependencies (e.g. Service -> Enum), delete them too if safe.
                                    if (f.associatedOffsets && f.associatedOffsets.length > 0) {
                                        f.associatedOffsets.forEach(assocOffset => {
                                            // Ensure not out of bounds
                                            if (assocOffset + 0x50 < newBuffer.length) {
                                                neuterKeyNode(newBuffer, assocOffset, mainView);
                                            }
                                        });
                                    }

                                    workingScanResults[scanIndex] = { ...f, isDeleted: true };
                                }
                                processedGlobal++;
                            } catch (e) {
                                console.warn("Skipping key error", e);
                            }
                        } else {
                            skippedSafety++;
                        }
                    }
                    scanIndex++;
                    chunkProcessed++;
                }

                const pct = totalActive > 0 ? Math.floor((scanIndex / sourceResults.length) * 100) : 100;
                updateOverlay(pct, `${processedGlobal} Neutered / ${skippedSafety} Locked`, "Sysinternals Heuristics...");

                if (scanIndex >= workingScanResults.length) {
                    clearInterval(interval);
                    updateOverlay(100, "Done!", "Finalizing...");

                    setTimeout(() => {
                        setFileData(newBuffer);
                        setScanResults(workingScanResults);
                        setActionStatus('completed');
                        addLog(`Batch Complete: ${processedGlobal} processed. ${skippedSafety} skipped (Critical/Safety).`);
                        
                        setTimeout(() => removeOverlay(), 500);
                        setTimeout(() => setActionStatus('idle'), 5000);
                        
                        setTimeout(() => alert(`Operation Complete.\n\nNeutered: ${processedGlobal}\nSkipped (Safety Locked): ${skippedSafety}\n\nPersistence items and Search results were prioritized.`), 600);
                    }, 500); 
                }
            }, 50); 
       } catch (err) {
            const errMsg = "Batch Processing Exception: " + err;
            alert(errMsg);
            removeOverlay();
            setActionStatus('idle');
       }
  };

  const triggerBatchDelete = useCallback(() => {
    const currentResults = scanResultsRef.current;
    const currentData = fileDataRef.current;

    if (!currentData || !currentResults || currentResults.length === 0) {
        return;
    }

    const activeThreatsCount = currentResults.reduce((acc, f) => f.isDeleted ? acc : acc + 1, 0);

    if (activeThreatsCount === 0) {
        alert("All detected threats have already been neutered.");
        return;
    }

    setBatchNeuterCount(activeThreatsCount);
    setShowConfirmModal(true); 
  }, []);

  const executeBatchDelete = useCallback(() => {
      setShowConfirmModal(false); 

      const currentData = fileDataRef.current;
      const currentResults = scanResultsRef.current;

      if (!currentData || !currentResults) {
          alert("Error: Data reference lost. Please reload file.");
          return;
      }

      setActionStatus('processing');
      injectOverlay();
      updateOverlay(0, "Initializing...", "Allocating Buffer");

      setTimeout(() => {
          startProcessingLoop(currentData, currentResults, batchNeuterCount);
      }, 100);
  }, [batchNeuterCount]);

  const verifyIntegrity = () => {
      if (!fileData) return;
      
      addLog("Starting Integrity Verification...");
      const view = new DataView(fileData.buffer, fileData.byteOffset, fileData.byteLength);
      
      const sig = view.getUint32(0, true);
      const isSigValid = sig === 0x66676572;
      addLog(`Signature: ${isSigValid ? 'OK' : 'FAIL'} (0x${sig.toString(16)})`);

      const lenHeader = view.getUint32(0x28, true);
      const expectedLen = fileData.length - 0x1000;
      const isLenValid = lenHeader === expectedLen;
      addLog(`Length Header: 0x${lenHeader.toString(16)} (File: 0x${expectedLen.toString(16)}) - ${isLenValid ? 'OK' : 'MISMATCH'}`);

      const seq1 = view.getUint32(0x04, true);
      const seq2 = view.getUint32(0x08, true);
      const isSeqValid = seq1 === seq2;
      addLog(`Sequence: ${seq1} vs ${seq2} - ${isSeqValid ? 'OK' : 'MISMATCH (DIRTY)'}`);

      if (!isSigValid || !isLenValid) {
          alert("CRITICAL INTEGRITY FAILURE.\n\nFile is corrupt and WILL BOOT LOOP Windows.\nCheck diagnostic log below.");
      } else {
          alert(`Integrity OK.\n\nSeq: ${seq1}\nSize: ${fileData.length} bytes\n\nReady for Download.`);
      }
  };

  const handleDownload = () => {
    if (!fileData) return;
    
    // v6.4 FIX: Fix Header Checksum, Sequence AND LENGTH
    const newBuffer = new Uint8Array(fileData);
    const logs = fixHiveHeader(newBuffer);
    logs.forEach(l => addLog(l));

    const blob = new Blob([newBuffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob as Blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName ? `neutered_${fileName}` : 'neutered_hive.dat';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100 font-sans selection:bg-cyan-500/30 relative">
      
      {/* CUSTOM MODAL */}
      {showConfirmModal && (
        <ConfirmationModal 
            count={batchNeuterCount} 
            onConfirm={executeBatchDelete} 
            onCancel={() => { setShowConfirmModal(false); }} 
        />
      )}

      <header className="h-14 border-b border-gray-800 bg-gray-950 flex items-center px-6 justify-between shrink-0 z-20 shadow-md">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-red-900 to-gray-900 rounded flex items-center justify-center text-red-400 font-bold border border-red-800">H</div>
          <div>
            <h1 className="font-bold text-lg tracking-wide text-gray-100 leading-none flex items-center gap-2">
              HiveMind <span className="text-blue-500">v9.0</span>
            </h1>
          </div>
        </div>
        
        {/* Search Bar */}
        {fileData && (
          <div className="flex-1 max-w-xl mx-8 relative">
              <input 
                  type="text" 
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  onKeyDown={handleSearchKey}
                  placeholder="Search keys... (Press Enter)"
                  className="w-full bg-black/40 border border-gray-800 rounded-lg px-4 py-1.5 text-xs text-cyan-300 focus:outline-none focus:border-cyan-700 placeholder-gray-600 transition-colors"
              />
              <button 
                onClick={performSearch}
                className="absolute right-2 top-1.5 p-0.5 hover:bg-gray-800 rounded text-gray-500 hover:text-cyan-400 transition-colors"
                title="Perform Search"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
              </button>
          </div>
        )}

        <div className="flex items-center gap-4">
             {fileData && (
               <>
                 <button onClick={verifyIntegrity} className="px-3 py-1.5 bg-purple-900/20 hover:bg-purple-900/40 text-purple-400 border border-purple-900/50 text-xs font-bold rounded uppercase tracking-wide">
                   Verify Hive
                 </button>
                 <button onClick={() => logInputRef.current?.click()} className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 text-xs font-bold rounded uppercase tracking-wide">
                   Load Logs
                 </button>
                 <button onClick={performScan} disabled={isScanning} className={`px-3 py-1.5 text-xs font-bold rounded border border-gray-700 uppercase tracking-wide ${isScanning ? 'bg-gray-800 text-gray-500' : 'bg-red-900/20 hover:bg-red-900/40 text-red-400 border-red-900/50'}`}>
                   {isScanning ? 'Scanning...' : 'Threat Scan'}
                 </button>
                 <button onClick={handleDownload} className="px-3 py-1.5 bg-green-900/20 hover:bg-green-900/40 text-green-400 border border-green-900/50 text-xs font-bold rounded uppercase tracking-wide">
                   Download Hive
                 </button>
               </>
             )}
             <div className="flex gap-2 ml-2">
                <input type="file" ref={logInputRef} className="hidden" multiple accept=".log,.log1,.log2" onChange={handleLogUpload} />
                <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileUpload}/>
                {/* Fallback Legacy Upload - Hidden if Native works, or handled inside function */}
                <button onClick={handleNativeFileOpen} className="p-1.5 bg-gray-800 hover:bg-gray-700 rounded text-gray-400 hover:text-white border border-gray-700" title="Open Local Hive">
                   <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z" /></svg>
                </button>
             </div>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {fileData ? (
          <>
            <div className="flex-1 relative flex flex-col min-w-0">
                <div className="h-8 bg-gray-900 border-b border-gray-800 flex items-center px-4 text-xs text-gray-500 gap-4">
                   <span className="text-gray-500 font-mono">OFFSET: {selectionOffset.toString(16).toUpperCase()}</span>
                   <span className={scanResults.length > 0 ? "text-red-400 font-bold" : ""}>{scanResults.length} THREATS</span>
                   {reconcileStats && (
                       <span className="text-green-500 ml-auto">LOGS MERGED: {reconcileStats.logsProcessed} (SEQ: {reconcileStats.finalSequence})</span>
                   )}
                </div>
                <div className="flex-1 overflow-hidden relative">
                   <HexViewer 
                     data={fileData} baseOffset={0} onSelectionChange={onSelectionChange}
                     selectedStart={selectionRange?.start ?? null} selectedEnd={selectionRange?.end ?? null}
                   />
                </div>
                
                {/* v7.0 DIAGNOSTIC TERMINAL (RESTORED) */}
                <div className="h-32 bg-black border-t border-gray-800 p-2 overflow-y-auto font-mono text-[10px] text-green-400 opacity-90 z-30">
                   <div className="flex justify-between border-b border-gray-800 mb-1 pb-1 text-gray-500">
                      <span>DIAGNOSTIC & DIFF LOG</span>
                      <button onClick={() => setLogs([])} className="hover:text-white">CLEAR</button>
                   </div>
                   {logs.length === 0 && <div className="text-gray-600 italic">Ready.</div>}
                   {logs.map((l, i) => <div key={i}>{l}</div>)}
                </div>

            </div>
            <AnalysisPanel 
              selectedBytes={selectedBytes} selectionOffset={selectionOffset} scanResults={scanResults}
              onSelectFinding={handleSelectFinding} onDeleteFinding={handleDeleteKey}
              onDeleteAll={triggerBatchDelete} onPatchBytes={handlePatchBytes} onContextChange={handleContextChange}
              onModeChange={setAiMode} actionStatus={actionStatus} 
            />
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center flex-col gap-8 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900 to-gray-950">
             <button onClick={handleNativeFileOpen} className="px-6 py-2.5 bg-red-900 hover:bg-red-800 text-white font-medium rounded-lg border border-red-800 shadow-lg shadow-red-900/30 flex items-center gap-2">
                 <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z" /></svg>
                 Open Hive File
             </button>
             <div className="text-gray-600 text-xs">Supports SYSTEM, SOFTWARE, SAM, NTUSER.DAT</div>
          </div>
        )}
      </div>
      
      <footer className="h-7 bg-gray-900 border-t border-gray-800 flex items-center px-4 text-[10px] text-gray-600 justify-between shrink-0 select-none">
        <div className="flex gap-6 font-mono">
           <span>ENGINE: <span className="text-cyan-600">GEMINI-2.5-FLASH</span></span>
           <span>MODE: <span className="text-red-400 uppercase">{aiMode}</span></span>
        </div>
        <div className="opacity-50">v9.0 (SYSINTERNALS LOGIC)</div>
      </footer>
    </div>
  );
};

export default App;