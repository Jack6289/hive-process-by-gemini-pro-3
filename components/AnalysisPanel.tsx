
import React, { useState } from 'react';
import { AnalysisMode, AnalysisResult, ScanFinding } from '../types';
import { analyzeHiveChunk } from '../services/geminiService';

interface AnalysisPanelProps {
  selectedBytes: Uint8Array | null;
  selectionOffset: number;
  scanResults: ScanFinding[];
  onSelectFinding: (finding: ScanFinding) => void;
  onDeleteFinding?: (finding: ScanFinding) => void;
}

const AnalysisPanel: React.FC<AnalysisPanelProps> = ({ 
  selectedBytes, 
  selectionOffset, 
  scanResults, 
  onSelectFinding,
  onDeleteFinding 
}) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [activeMode, setActiveMode] = useState<AnalysisMode | null>(null);

  const isKeyNode = selectedBytes && selectedBytes.length >= 2 && selectedBytes[0] === 0x6E && selectedBytes[1] === 0x6B;
  const isAlreadyDeleted = selectedBytes && selectedBytes.length >= 2 && selectedBytes[0] === 0x58 && selectedBytes[1] === 0x58;

  const activeFinding = scanResults.find(f => f.offset === selectionOffset);

  const handleAnalyze = async (mode: AnalysisMode) => {
    if (!selectedBytes || selectedBytes.length === 0) return;
    setActiveMode(mode);
    setLoading(true);
    setResult(null);
    try {
      const hexString = Array.from(selectedBytes)
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join(' ');
      const response = await analyzeHiveChunk(hexString, mode, selectionOffset);
      setResult(response);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const severityColor = (s: string) => {
    switch(s) {
      case 'critical': return 'text-red-500 border-red-900 bg-red-950/50';
      case 'high': return 'text-orange-500 border-orange-900 bg-orange-950/50';
      case 'medium': return 'text-yellow-500 border-yellow-900 bg-yellow-950/50';
      default: return 'text-cyan-500 border-cyan-900 bg-cyan-950/50';
    }
  };

  const modes = [
    { id: AnalysisMode.GHOST_VIRTUALIZATION, label: 'Virtualization / Ghost Keys', desc: 'Detect keys existing only in memory/containers.', icon: '👻' },
    { id: AnalysisMode.ACL_CLOAKING, label: 'ACL Cloaking / Hidden', desc: 'Find keys hidden from System/Admins.', icon: '🛡️' },
    { id: AnalysisMode.PERMISSION_BYPASS, label: 'Access Denied / Permission', desc: 'Analyze ownership and bypass checks.', icon: '🚫' },
    { id: AnalysisMode.COMPOSITE_LAYERING, label: 'Composite / Merged Keys', desc: 'Identify dynamic composite views.', icon: '🧩' },
    { id: AnalysisMode.INTEGRITY_RECOVERY, label: 'Illegal Chars / Corrupt', desc: 'Fix null bytes and broken headers.', icon: '🩹' },
  ];

  return (
    <div className="h-full flex flex-col bg-gray-950 border-l border-gray-800 w-[420px] shadow-2xl z-10">
      <div className="p-5 border-b border-gray-800 bg-gray-900/50">
        <h2 className="text-lg font-bold text-cyan-400 flex items-center gap-2 tracking-wide">
           <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
           Binary Forensic Lab <span className="text-[9px] ml-auto text-purple-400 border border-purple-900 bg-purple-950 px-1 rounded">v2.2 LOG REPLAY</span>
        </h2>
        <p className="text-[10px] text-gray-500 mt-1 font-mono">DETERMINISTIC_ENGINE (NO TRAINING REQ)</p>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        
        {/* Automated Scan Results */}
        {scanResults.length > 0 && (
           <div className="space-y-2">
             <div className="text-[10px] font-bold text-cyan-500 uppercase tracking-widest flex justify-between">
                <span>Inference Results ({scanResults.length})</span>
                <span className="animate-pulse">● LIVE</span>
             </div>
             <div className="max-h-60 overflow-y-auto border border-gray-800 rounded-lg bg-black/20">
                {scanResults.map((finding) => {
                  const isVerified = finding.confidence >= 0.9;
                  const isPartial = finding.type === 'SEARCH_MATCH' && finding.confidence < 0.9;
                  
                  return (
                  <div 
                    key={finding.id}
                    onClick={() => onSelectFinding(finding)}
                    className={`p-3 border-b border-gray-800 cursor-pointer transition-colors group flex flex-col gap-1
                      ${finding.isDeleted ? 'bg-red-950/30 opacity-60' : 'hover:bg-cyan-900/20'}
                      ${isVerified ? 'bg-blue-900/5' : ''}
                      ${isPartial ? 'opacity-75' : ''}
                      ${finding.type === 'RECOVERED_KEY' ? 'bg-amber-900/10 border-l-2 border-amber-600' : ''}
                      ${finding.type === 'DATA_REMNANT' ? 'bg-gray-800/30 border-2 border-dashed border-gray-700 opacity-80' : ''}
                    `}
                  >
                    <div className="flex justify-between items-center">
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border
                        ${finding.type === 'VIRTUALIZED' ? 'bg-purple-900/30 text-purple-300 border-purple-800' : ''}
                        ${finding.type === 'STUBBORN' ? 'bg-red-900/30 text-red-300 border-red-800' : ''}
                        ${finding.type === 'HIDDEN' ? 'bg-orange-900/30 text-orange-300 border-orange-800' : ''}
                        ${finding.type === 'CORRUPT' ? 'bg-yellow-900/30 text-yellow-300 border-yellow-800' : ''}
                        ${finding.type === 'SEARCH_MATCH' && isVerified ? 'bg-blue-900/30 text-blue-300 border-blue-800' : ''}
                        ${finding.type === 'SEARCH_MATCH' && isPartial ? 'bg-gray-800/50 text-gray-400 border-gray-700' : ''}
                        ${finding.type === 'RECOVERED_KEY' ? 'bg-amber-900/30 text-amber-300 border-amber-800' : ''}
                        ${finding.type === 'DATA_REMNANT' ? 'bg-gray-700 text-gray-400 border-gray-600' : ''}
                        ${!['VIRTUALIZED', 'STUBBORN', 'HIDDEN', 'CORRUPT', 'SEARCH_MATCH', 'RECOVERED_KEY', 'DATA_REMNANT'].includes(finding.type) ? 'bg-gray-800 text-gray-300' : ''}
                      `}>
                        {finding.type === 'SEARCH_MATCH' && isPartial ? 'PARTIAL MATCH' : finding.type}
                      </span>
                      <span className="text-[9px] font-mono text-gray-500">0x{finding.offset.toString(16).toUpperCase()}</span>
                    </div>
                    
                    <div className={`text-xs font-bold mt-1 truncate font-mono ${finding.isDeleted ? 'line-through' : 'text-gray-200'}`}>
                       {finding.name}
                    </div>
                    
                    {finding.inference ? (
                      <div className="mt-1 p-1.5 bg-black/40 rounded border border-gray-800">
                         <div className="text-[9px] text-gray-400 font-mono truncate mb-1" title={finding.inference.resolvedPath}>
                            <span className="text-cyan-700 mr-1">PATH:</span>{finding.inference.resolvedPath}
                         </div>
                         {finding.inference.heuristicWarnings.length > 0 && (
                           <div className="text-[9px] text-orange-400">
                             WARN: {finding.inference.heuristicWarnings[0]}
                           </div>
                         )}
                         <div className="text-[8px] text-gray-600 uppercase mt-1 flex justify-between">
                            <span>Confidence: {(finding.inference.pathConfidence * 100).toFixed(0)}%</span>
                            <span>P-CID: {finding.inference.parentCellIndex}</span>
                         </div>
                      </div>
                    ) : (
                       <div className="text-[10px] text-gray-500">{finding.description}</div>
                    )}
                  </div>
                )})}
             </div>
           </div>
        )}

        {/* Context Box */}
        <div className="bg-gray-900 p-4 rounded-lg border border-gray-800 shadow-inner">
           <div className="flex justify-between items-end mb-2">
             <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Buffer Context</span>
             {selectedBytes && (
               <span className="text-[10px] font-mono text-cyan-600 bg-cyan-950/30 px-2 py-0.5 rounded border border-cyan-900/50">
                 {selectedBytes.length} BYTES
               </span>
             )}
           </div>
           
           {selectedBytes ? (
             <div className="font-mono text-sm text-cyan-300/80 break-all leading-relaxed">
               OFFSET: <span className="text-white">0x{selectionOffset.toString(16).toUpperCase().padStart(8, '0')}</span>
               <div className="mt-3 pt-3 border-t border-gray-800">
                 {activeFinding && !activeFinding.isDeleted && (isKeyNode || activeFinding.type === 'RECOVERED_KEY') && (
                    <button
                      onClick={() => onDeleteFinding && onDeleteFinding(activeFinding)}
                      className="w-full py-2 bg-red-900/20 hover:bg-red-900/40 border border-red-900 text-red-400 text-xs font-bold rounded uppercase tracking-wide transition-all flex items-center justify-center gap-2"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                      Destroy / Patch Key Signature
                    </button>
                 )}
                 {isAlreadyDeleted && (
                    <div className="text-center py-2 bg-gray-800 rounded border border-gray-700 text-gray-400 text-xs font-bold">
                      KEY SIGNATURE DESTROYED (PATCHED)
                    </div>
                 )}
                 {!isKeyNode && !isAlreadyDeleted && activeFinding?.type !== 'RECOVERED_KEY' && (
                    <div className="text-[10px] text-gray-600 italic text-center">
                      Select a valid 'nk' record to enable binary patch tools.
                    </div>
                 )}
               </div>
             </div>
           ) : (
             <div className="text-sm text-gray-600 italic py-2 text-center">
               Select binary data manually or click an anomaly above.
             </div>
           )}
        </div>

        {/* Forensic Tools Grid */}
        <div>
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3">Forensic Modules</div>
          <div className="grid grid-cols-1 gap-3">
            {modes.map((m) => (
              <button
                key={m.id}
                onClick={() => handleAnalyze(m.id)}
                disabled={!selectedBytes || loading}
                className={`group relative flex items-center gap-4 p-3 rounded-lg border transition-all duration-200 text-left
                  ${loading && activeMode === m.id ? 'bg-cyan-900/20 border-cyan-500/50' : ''}
                  ${!selectedBytes 
                    ? 'bg-gray-900/50 border-gray-800 text-gray-600 cursor-not-allowed grayscale' 
                    : 'bg-gray-800 border-gray-700 hover:bg-gray-750 hover:border-cyan-600/50 hover:shadow-[0_0_10px_rgba(6,182,212,0.1)]'}
                `}
              >
                <div className="text-2xl group-hover:scale-110 transition-transform">{m.icon}</div>
                <div>
                   <div className={`text-sm font-bold ${!selectedBytes ? 'text-gray-600' : 'text-gray-200 group-hover:text-cyan-400'}`}>
                     {m.label}
                   </div>
                   <div className="text-[10px] text-gray-500 leading-tight mt-0.5">{m.desc}</div>
                </div>
                {loading && activeMode === m.id && (
                  <div className="absolute right-3 top-3">
                    <svg className="animate-spin h-4 w-4 text-cyan-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Results Display */}
        {result && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 border-t border-gray-800 pt-4">
            <div className={`p-4 rounded-lg border ${severityColor(result.severity)} mb-3 relative overflow-hidden`}>
               <div className="absolute top-0 right-0 p-2 opacity-10 text-6xl font-black select-none pointer-events-none">!</div>
               <div className="flex justify-between items-center mb-2 relative z-10">
                  <h3 className="font-bold text-sm uppercase tracking-wide">{result.title}</h3>
                  <span className="text-[9px] font-black uppercase px-2 py-0.5 rounded bg-black/30 border border-white/10">{result.severity}</span>
               </div>
               <p className="text-xs font-medium opacity-90 leading-relaxed relative z-10">{result.description}</p>
            </div>

            <div className="space-y-3">
               <div className="bg-black/20 p-3 rounded border border-gray-800">
                 <h4 className="text-[10px] text-gray-500 uppercase tracking-widest mb-2">Deep Inspection</h4>
                 <p className="text-xs text-cyan-100/80 font-mono leading-relaxed whitespace-pre-wrap">{result.technicalDetails}</p>
               </div>

               <div className="bg-cyan-900/10 p-3 rounded border border-cyan-900/30">
                 <h4 className="text-[10px] text-cyan-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                   <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                   Suggested Remediation
                 </h4>
                 <p className="text-xs text-gray-300 leading-relaxed">{result.recommendation}</p>
               </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalysisPanel;
