
import React, { useState, useRef } from 'react';
import HexViewer from './components/HexViewer';
import AnalysisPanel from './components/AnalysisPanel';
import { scanHiveForAnomalies, searchHive } from './services/hiveScanner';
import { reconcileLog, ReconcileResult } from './services/logReconciler';
import { ScanFinding } from './types';

const App: React.FC = () => {
  const [fileData, setFileData] = useState<Uint8Array | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [selectedBytes, setSelectedBytes] = useState<Uint8Array | null>(null);
  const [selectionOffset, setSelectionOffset] = useState<number>(0);
  
  const [scanResults, setScanResults] = useState<ScanFinding[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [reconcileStats, setReconcileStats] = useState<ReconcileResult | null>(null);
  
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
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const handleLogUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !fileData) return;

    setIsScanning(true);
    const reader = new FileReader();
    reader.onload = (event) => {
      if (event.target?.result) {
        try {
          const logBuffer = new Uint8Array(event.target.result as ArrayBuffer);
          const result = reconcileLog(fileData, logBuffer);
          
          setFileData(result.patchedBuffer);
          setReconcileStats(result);
          
          // Auto re-scan after patch
          setTimeout(() => {
             const findings = scanHiveForAnomalies(result.patchedBuffer);
             setScanResults(findings);
             setIsScanning(false);
          }, 100);

        } catch (err) {
          alert("Failed to parse log file. Ensure it is a valid transaction log.");
          setIsScanning(false);
        }
      }
    };
    reader.readAsArrayBuffer(file);
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

  const handleDeleteKey = (finding: ScanFinding) => {
    if (!fileData) return;

    const newBuffer = new Uint8Array(fileData); 
    const offset = finding.offset;
    
    newBuffer[offset] = 0x58;
    newBuffer[offset + 1] = 0x58;
    
    setFileData(newBuffer);
    
    setScanResults(prev => prev.map(f => 
      f.id === finding.id ? { ...f, isDeleted: true } : f
    ));

    const len = finding.length;
    setSelectedBytes(newBuffer.slice(offset, offset + len));
  };

  const handleDownload = () => {
    if (!fileData) return;
    const blob = new Blob([fileData], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "modified_" + fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const onSelectionChange = (start: number, end: number) => {
    if (!fileData) return;
    const maxLen = 1024; 
    const len = end - start + 1;
    
    let actualEnd = end;
    if (len > maxLen) {
        actualEnd = start + maxLen - 1;
    }

    const slice = fileData.slice(start, actualEnd + 1);
    setSelectedBytes(slice);
    setSelectionOffset(start);
  };

  const handleSelectFinding = (finding: ScanFinding) => {
    if (!fileData) return;
    const start = finding.offset;
    const end = finding.offset + finding.length;
    const slice = fileData.slice(start, end);
    setSelectedBytes(slice);
    setSelectionOffset(start);
  };

  const loadAdvancedDemoData = () => {
     // ... (existing demo logic, kept briefly for simplicity)
     // For now just clear
     setScanResults([]);
     alert("Please load a real file to test Log Reconciliation.");
  };

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100 font-sans selection:bg-cyan-500/30">
      <header className="h-14 border-b border-gray-800 bg-gray-950 flex items-center px-6 justify-between shrink-0 z-20 shadow-md">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-cyan-900 to-gray-900 rounded flex items-center justify-center text-cyan-400 font-bold border border-cyan-800 shadow-[0_0_10px_rgba(34,211,238,0.2)]">
            H
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-wide text-gray-100 leading-none">
              HiveMind <span className="text-cyan-500">Forensics</span>
            </h1>
            <p className="text-[9px] text-gray-500 tracking-widest uppercase">Advanced Registry Binary Processor</p>
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
                    placeholder="Search Path..." 
                    className="bg-transparent text-xs text-gray-200 px-3 py-1.5 outline-none w-40"
                 />
                 <button type="submit" className="px-2 py-1.5 bg-gray-800 text-gray-400 hover:text-cyan-400 border-l border-gray-700">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                 </button>
               </form>

               <div className="h-6 w-px bg-gray-800 mx-2"></div>

               <input 
                  type="file" 
                  ref={logInputRef} 
                  className="hidden" 
                  accept=".log,.log1,.log2"
                  onChange={handleLogUpload}
               />
               <button
                 onClick={() => logInputRef.current?.click()}
                 className="px-3 py-1.5 text-xs font-bold rounded border bg-purple-900/20 hover:bg-purple-900/40 border-purple-900/50 text-purple-300 uppercase tracking-wide flex items-center gap-2"
                 title="Load .LOG file to recover recent keys"
               >
                 {reconcileStats ? `Log Applied (${reconcileStats.patchesApplied})` : 'Load Transaction Log'}
               </button>

               <button
                 onClick={performScan}
                 disabled={isScanning}
                 className={`px-3 py-1.5 text-xs font-bold rounded border uppercase tracking-wide flex items-center gap-2
                   ${isScanning 
                     ? 'bg-gray-800 border-gray-700 text-gray-400' 
                     : 'bg-cyan-900/10 hover:bg-cyan-900/30 text-cyan-400 border-cyan-900/50 transition-all'}
                 `}
               >
                 {isScanning ? 'Scanning...' : 'Deep Scan'}
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
              title="Open File"
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
                   <span>VIEWER: HEXADECIMAL</span>
                   <span className="text-gray-700">|</span>
                   <span>OFFSET: {selectionOffset.toString(16).toUpperCase()}</span>
                   <span className="text-gray-700">|</span>
                   <span className={scanResults.length > 0 ? "text-cyan-400" : ""}>
                      {scanResults.length} ITEMS FOUND
                   </span>
                   {reconcileStats && (
                     <>
                       <span className="text-gray-700">|</span>
                       <span className="text-purple-400 animate-pulse">
                          RECONCILED: {reconcileStats.patchesApplied} PAGES PATCHED
                       </span>
                     </>
                   )}
                </div>
                <div className="flex-1 overflow-hidden relative">
                   <HexViewer 
                     data={fileData} 
                     baseOffset={0}
                     onSelectionChange={onSelectionChange}
                   />
                </div>
            </div>
            <AnalysisPanel 
              selectedBytes={selectedBytes} 
              selectionOffset={selectionOffset}
              scanResults={scanResults}
              onSelectFinding={handleSelectFinding}
              onDeleteFinding={handleDeleteKey}
            />
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center flex-col gap-8 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900 to-gray-950">
             <div className="relative group cursor-pointer" onClick={() => fileInputRef.current?.click()}>
                <div className="absolute -inset-1 bg-gradient-to-r from-cyan-600 to-blue-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                <div className="relative w-32 h-32 bg-gray-900 border border-gray-700 rounded-xl flex items-center justify-center shadow-2xl">
                    <svg className="w-16 h-16 text-cyan-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
                </div>
             </div>
             
             <div className="text-center space-y-2">
               <h3 className="text-2xl font-bold text-gray-200 tracking-tight">HiveMind Forensics v2.2</h3>
               <p className="text-gray-500 max-w-md mx-auto leading-relaxed">
                 Specialized Registry Hive analyzer with <span className="text-cyan-400">Transaction Log Replay</span>.
                 <br/>
                 Load .LOG files to reconcile memory-only keys and recover latest changes.
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
                    className="px-6 py-2.5 bg-cyan-800 hover:bg-cyan-700 text-white font-medium rounded-lg border border-cyan-700 transition-all hover:scale-105 shadow-lg shadow-cyan-900/30"
                >
                    Open Registry Hive
                </button>
             </div>
          </div>
        )}
      </div>
      
      <footer className="h-7 bg-gray-900 border-t border-gray-800 flex items-center px-4 text-[10px] text-gray-600 justify-between shrink-0 select-none">
        <div className="flex gap-6 font-mono">
           <span>ENGINE: <span className="text-cyan-600">GEMINI-2.5-FLASH-PREVIEW</span></span>
           <span>SCANNER: <span className="text-purple-400">LOG_REPLAY_ENABLED</span></span>
           <span>STATUS: <span className={isScanning ? "text-yellow-500 animate-pulse" : "text-green-600"}>{isScanning ? 'PROCESSING...' : 'READY'}</span></span>
        </div>
        <div className="opacity-50">
           BUILD 2024.10.5 // v2.2 LOG RECONCILIATION
        </div>
      </footer>
    </div>
  );
};

export default App;
