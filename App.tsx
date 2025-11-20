
import React, { useState, useRef } from 'react';
import HexViewer from './components/HexViewer';
import AnalysisPanel from './components/AnalysisPanel';
import { scanHiveForAnomalies, searchHive } from './services/hiveScanner';
import { reconcileMultipleLogs, ReconcileResult } from './services/logReconciler';
import { ScanFinding } from './types';

const App: React.FC = () => {
  const [fileData, setFileData] = useState<Uint8Array | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [selectedBytes, setSelectedBytes] = useState<Uint8Array | null>(null);
  const [selectionOffset, setSelectionOffset] = useState<number>(0);
  
  const [scanResults, setScanResults] = useState<ScanFinding[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [jumpQuery, setJumpQuery] = useState('');
  const [reconcileStats, setReconcileStats] = useState<ReconcileResult | null>(null);
  
  // Selection State
  const [selectionRange, setSelectionRange] = useState<{start: number, end: number} | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const logInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      if (event.target?.result) {
        const buffer = event.target.result as ArrayBuffer;
        const uint8 = new Uint8Array(buffer.slice(0, 32 * 1024 * 1024));
        setFileData(uint8);
        setFileName(file.name);
        setScanResults([]); 
        setReconcileStats(null);
        setSelectionRange(null);
        setSelectedBytes(null);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const handleLogUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0 || !fileData) return;

    setIsScanning(true);

    // Read all selected log files
    const readers = Array.from(files).map(file => {
      return new Promise<Uint8Array>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (ev) => {
          if (ev.target?.result) {
            resolve(new Uint8Array(ev.target.result as ArrayBuffer));
          } else {
            reject(new Error("Empty file"));
          }
        };
        reader.onerror = reject;
        reader.readAsArrayBuffer(file);
      });
    });

    try {
      const logBuffers = await Promise.all(readers);
      
      // Process all logs (Sort & Apply)
      const result = reconcileMultipleLogs(fileData, logBuffers);
      
      setFileData(result.patchedBuffer);
      setReconcileStats(result);
      
      // Auto re-scan after patch
      setTimeout(() => {
         const findings = scanHiveForAnomalies(result.patchedBuffer);
         setScanResults(findings);
         setIsScanning(false);
      }, 100);

    } catch (err) {
      console.error(err);
      alert("Failed to parse log files. Ensure they are valid Registry Transaction Logs.");
      setIsScanning(false);
    }
  };

  const performScan = () => {
    if (!fileData) return;
    setIsScanning(true);
    
    setTimeout(() => {
      const findings = scanHiveForAnomalies(fileData);
      setScanResults(findings);
      setIsScanning(false);
    }, 100);
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!fileData || !searchQuery.trim()) return;

    setIsScanning(true);
    setTimeout(() => {
      const findings = searchHive(fileData, searchQuery.trim());
      setScanResults(findings);
      setIsScanning(false);
    }, 50);
  };

  const handleJump = (e: React.FormEvent) => {
    e.preventDefault();
    if (!fileData || !jumpQuery.trim()) return;

    // Parse input (handle 0x prefix or pure decimal)
    let offset = NaN;
    if (jumpQuery.trim().toLowerCase().startsWith('0x')) {
       offset = parseInt(jumpQuery.trim(), 16);
    } else {
       offset = parseInt(jumpQuery.trim(), 10);
       // Fallback: if user typed hex without 0x but it failed decimal or looks hex
       if (isNaN(offset) && /^[0-9A-Fa-f]+$/.test(jumpQuery.trim())) {
          offset = parseInt(jumpQuery.trim(), 16);
       }
    }

    if (isNaN(offset) || offset < 0 || offset >= fileData.length) {
       alert("Invalid or out of bounds offset.");
       return;
    }

    // Check if this offset is part of a known finding to select the whole thing
    const finding = scanResults.find(f => offset >= f.offset && offset < f.offset + f.length);
    
    let start = offset;
    let end = offset; // Default single byte
    
    if (finding) {
      start = finding.offset;
      end = finding.offset + finding.length - 1;
    } else {
      // Default to 16 bytes view if not a specific finding
      end = Math.min(offset + 15, fileData.length - 1);
    }

    // Update Selection
    onSelectionChange(start, end);
  };

  // Safely "neuters" a key without breaking the tree structure.
  const neuterKeyNode = (buffer: Uint8Array, offset: number) => {
      const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      view.setUint32(offset + 0x14, 0, true);
      view.setUint32(offset + 0x18, 0, true);
      view.setInt32(offset + 0x1C, -1, true);
      view.setInt32(offset + 0x20, -1, true);
      view.setUint32(offset + 0x24, 0, true);
      view.setInt32(offset + 0x28, -1, true);
      view.setInt32(offset + 0x2C, -1, true);
      view.setInt32(offset + 0x30, -1, true);
  };

  const handleDeleteKey = (finding: ScanFinding) => {
    if (!fileData) return;

    const newBuffer = new Uint8Array(fileData); 
    const offset = finding.offset;
    neuterKeyNode(newBuffer, offset);

    setFileData(newBuffer);
    
    setScanResults(prev => prev.map(f => 
      f.id === finding.id ? { ...f, isDeleted: true } : f
    ));

    const len = finding.length;
    onSelectionChange(offset, offset + len - 1, newBuffer);
  };

  const handlePatchBytes = (offset: number, bytes: Uint8Array) => {
    if (!fileData) return;
    const newBuffer = new Uint8Array(fileData);
    
    if (offset + bytes.length > newBuffer.length) {
        alert("Patch exceeds file boundaries.");
        return;
    }

    newBuffer.set(bytes, offset);
    setFileData(newBuffer);
    
    if (selectionRange) {
        onSelectionChange(selectionRange.start, selectionRange.end, newBuffer);
    }
  };

  const handleDeleteAllFindings = () => {
    if (!fileData) return;
    const activeCount = scanResults.filter(f => !f.isDeleted).length;
    if (activeCount === 0) return;
    if (!window.confirm(`⚠️ SAFE NEUTER WARNING ⚠️\n\nProceed to empty ${activeCount} keys?`)) return;

    const newBuffer = new Uint8Array(fileData);
    const updatedResults = scanResults.map(f => {
      if (f.isDeleted) return f;
      if (f.offset + 0x34 < newBuffer.length) {
           neuterKeyNode(newBuffer, f.offset);
           return { ...f, isDeleted: true };
      }
      return f;
    });

    setFileData(newBuffer);
    setScanResults(updatedResults);
    if (selectionRange) {
       onSelectionChange(selectionRange.start, selectionRange.end, newBuffer);
    }
  };

  const finalizeHiveHeader = (buffer: Uint8Array, explicitDataSize?: number) => {
    if (buffer.length < 0x200) return;
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const seq1 = view.getUint32(0x04, true);
    const seq2 = view.getUint32(0x08, true);
    const newSeq = Math.max(seq1, seq2) + 1;
    
    view.setUint32(0x04, newSeq, true);
    view.setUint32(0x08, newSeq, true);
    const dataSize = explicitDataSize !== undefined ? explicitDataSize : (buffer.length - 0x1000);
    view.setUint32(0x28, dataSize, true);
    let checksum = 0;
    for (let i = 0; i < 0x1FC; i += 4) {
      checksum ^= view.getUint32(i, true);
    }
    view.setUint32(0x1FC, checksum, true);
  };

  const handleDownload = () => {
    if (!fileData) return;
    let finalBuffer = fileData;
    const remainder = fileData.length % 4096;
    
    if (remainder !== 0) {
       const padding = 4096 - remainder;
       const tmp = new Uint8Array(fileData.length + padding);
       tmp.set(fileData);
       finalBuffer = tmp;
    }
    
    const validDataSize = finalBuffer.length - 0x1000;
    finalizeHiveHeader(finalBuffer, validDataSize);

    const blob = new Blob([finalBuffer], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "v3_healed_" + fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const onSelectionChange = (start: number, end: number, customBuffer?: Uint8Array) => {
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
  };

  const handleContextChange = (offset: number, len: number) => {
     if (!fileData) return;
     if (offset < 0 || offset >= fileData.length) return;
     let end = offset + len - 1;
     if (end >= fileData.length) end = fileData.length - 1;
     onSelectionChange(offset, end);
  };

  const handleSelectFinding = (finding: ScanFinding) => {
    if (!fileData) return;
    const start = finding.offset;
    const end = finding.offset + finding.length - 1;
    onSelectionChange(start, end);
  };

  const loadAdvancedDemoData = () => {
     setScanResults([]);
     alert("Please load a real file to test Log Reconciliation.");
  };

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100 font-sans selection:bg-cyan-500/30">
      <header className="h-14 border-b border-gray-800 bg-gray-950 flex items-center px-6 justify-between shrink-0 z-20 shadow-md">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-red-900 to-gray-900 rounded flex items-center justify-center text-red-400 font-bold border border-red-800 shadow-[0_0_15px_rgba(220,38,38,0.2)]">
            H
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-wide text-gray-100 leading-none">
              HiveMind <span className="text-red-500">v3.0</span>
            </h1>
            <p className="text-[9px] text-gray-500 tracking-widest uppercase">AI Rootkit & Malware Engine</p>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          {fileData && (
            <>
               <form onSubmit={handleSearch} className="flex items-center bg-gray-900 rounded border border-gray-700 overflow-hidden focus-within:border-cyan-600 transition-colors">
                 <input 
                    type="text" 
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search..." 
                    className="bg-transparent text-xs text-gray-200 px-3 py-1.5 outline-none w-40"
                 />
                 <button type="submit" className="px-2 py-1.5 bg-gray-800 text-gray-400 hover:text-cyan-400 border-l border-gray-700">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                 </button>
               </form>

               <form onSubmit={handleJump} className="flex items-center bg-gray-900 rounded border border-gray-700 overflow-hidden focus-within:border-cyan-600 transition-colors">
                 <input 
                    type="text" 
                    value={jumpQuery}
                    onChange={(e) => setJumpQuery(e.target.value)}
                    placeholder="Jump 0x..." 
                    className="bg-transparent text-xs text-gray-200 px-3 py-1.5 outline-none w-24 font-mono"
                 />
                 <button type="submit" className="px-2 py-1.5 bg-gray-800 text-gray-400 hover:text-cyan-400 border-l border-gray-700">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 9l3 3m0 0l-3 3m3-3H8m13 0a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                 </button>
               </form>

               <div className="h-6 w-px bg-gray-800 mx-2"></div>

               <input 
                  type="file" 
                  multiple
                  ref={logInputRef} 
                  className="hidden" 
                  accept=".log,.log1,.log2"
                  onChange={handleLogUpload}
               />
               <button
                 onClick={() => logInputRef.current?.click()}
                 className="px-3 py-1.5 text-xs font-bold rounded border bg-purple-900/20 hover:bg-purple-900/40 border-purple-900/50 text-purple-300 uppercase tracking-wide flex items-center gap-2"
               >
                 {reconcileStats ? `Logs Merged (${reconcileStats.patchesApplied})` : 'Load Logs'}
               </button>

               <button
                 onClick={performScan}
                 disabled={isScanning}
                 className={`px-3 py-1.5 text-xs font-bold rounded border uppercase tracking-wide flex items-center gap-2
                   ${isScanning 
                     ? 'bg-gray-800 border-gray-700 text-gray-400' 
                     : 'bg-red-900/10 hover:bg-red-900/30 text-red-400 border-red-900/50 transition-all'}
                 `}
               >
                 {isScanning ? 'Deep Scanning...' : 'Threat Scan'}
               </button>

               <button
                 onClick={handleDownload}
                 className="px-3 py-1.5 text-xs font-bold rounded border bg-gray-800 hover:bg-gray-700 border-gray-700 text-gray-300 uppercase tracking-wide"
               >
                 Download
               </button>
            </>
          )}
          
          <div className="flex gap-2 ml-2">
            <input 
              type="file" 
              ref={fileInputRef} 
              className="hidden" 
              onChange={handleFileUpload}
            />
            <button 
              onClick={() => fileInputRef.current?.click()}
              className="p-1.5 bg-gray-800 hover:bg-gray-700 rounded text-gray-400 hover:text-white border border-gray-700"
            >
               <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" /></svg>
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
                   <span className="text-gray-700">|</span>
                   <span className={scanResults.length > 0 ? "text-red-400 font-bold" : ""}>
                      {scanResults.length} THREATS
                   </span>
                </div>
                <div className="flex-1 overflow-hidden relative">
                   <HexViewer 
                     data={fileData} 
                     baseOffset={0}
                     onSelectionChange={onSelectionChange}
                     selectedStart={selectionRange?.start ?? null}
                     selectedEnd={selectionRange?.end ?? null}
                   />
                </div>
            </div>
            <AnalysisPanel 
              selectedBytes={selectedBytes} 
              selectionOffset={selectionOffset}
              scanResults={scanResults}
              onSelectFinding={handleSelectFinding}
              onDeleteFinding={handleDeleteKey}
              onDeleteAll={handleDeleteAllFindings}
              onPatchBytes={handlePatchBytes}
              onContextChange={handleContextChange}
            />
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center flex-col gap-8 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900 to-gray-950">
             <div className="relative group cursor-pointer" onClick={() => fileInputRef.current?.click()}>
                <div className="absolute -inset-1 bg-gradient-to-r from-red-600 to-orange-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                <div className="relative w-32 h-32 bg-gray-900 border border-gray-700 rounded-xl flex items-center justify-center shadow-2xl">
                    <svg className="w-16 h-16 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" /></svg>
                </div>
             </div>
             
             <div className="text-center space-y-2">
               <h3 className="text-2xl font-bold text-gray-200 tracking-tight">HiveMind AI v3.0</h3>
               <p className="text-gray-500 max-w-md mx-auto leading-relaxed">
                 Rootkit & Malware Registry Engine.
                 <br/>
                 <span className="text-red-400">AI Auto-Heal</span> • <span className="text-cyan-400">Threat Intelligence</span> • <span className="text-green-400">Script Reconstruction</span>
               </p>
             </div>

             <div className="flex gap-4">
                <button 
                    onClick={loadAdvancedDemoData}
                    className="px-6 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-400 text-xs font-medium rounded-lg border border-gray-700 transition-all"
                >
                    Clear Data
                </button>
                <button 
                    onClick={() => fileInputRef.current?.click()}
                    className="px-6 py-2.5 bg-red-900 hover:bg-red-800 text-white font-medium rounded-lg border border-red-800 transition-all hover:scale-105 shadow-lg shadow-red-900/30"
                >
                    Load Infected Hive
                </button>
             </div>
          </div>
        )}
      </div>
      
      <footer className="h-7 bg-gray-900 border-t border-gray-800 flex items-center px-4 text-[10px] text-gray-600 justify-between shrink-0 select-none">
        <div className="flex gap-6 font-mono">
           <span>ENGINE: <span className="text-cyan-600">GEMINI-2.5-FLASH</span></span>
           <span>MODE: <span className="text-red-400">OFFENSIVE_DEFENSE_ENABLED</span></span>
           <span>STATUS: <span className={isScanning ? "text-yellow-500 animate-pulse" : "text-green-600"}>{isScanning ? 'ANALYZING...' : 'IDLE'}</span></span>
        </div>
        <div className="opacity-50">
           v3.0 (STABLE)
        </div>
      </footer>
    </div>
  );
};

export default App;
