
import React, { useState, useEffect } from 'react';
import { AnalysisMode, AnalysisResult, ScanFinding } from '../types';
import { analyzeHiveChunk } from '../services/geminiService';
import { repairKeyNode } from '../services/hiveScanner';

interface AnalysisPanelProps {
  selectedBytes: Uint8Array | null;
  selectionOffset: number;
  scanResults: ScanFinding[];
  onSelectFinding: (finding: ScanFinding) => void;
  onDeleteFinding?: (finding: ScanFinding) => void;
  onDeleteAll?: () => void; 
  onPatchBytes?: (offset: number, bytes: Uint8Array) => void;
  onContextChange?: (offset: number, length: number) => void;
  onModeChange?: (mode: string) => void;
  actionStatus?: 'idle' | 'starting' | 'processing' | 'completed';
}

// Optimized Component with Memoization to prevent unnecessary re-renders
const AnalysisPanel: React.FC<AnalysisPanelProps> = React.memo(({ 
  selectedBytes, 
  selectionOffset, 
  scanResults, 
  onSelectFinding,
  onDeleteFinding,
  onDeleteAll,
  onPatchBytes,
  onContextChange,
  onModeChange,
  actionStatus = 'idle'
}) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [activeMode, setActiveMode] = useState<AnalysisMode | null>(null);
  
  // Hex Editor State
  const [editBytes, setEditBytes] = useState<string[]>([]);
  const [isEditing, setIsEditing] = useState(false);

  // Context Input State
  const [offsetInput, setOffsetInput] = useState('');
  const [lengthInput, setLengthInput] = useState('');

  useEffect(() => {
    if (selectedBytes) {
      const hexArray = Array.from(selectedBytes).map((b: number) => b.toString(16).padStart(2, '0').toUpperCase());
      setEditBytes(hexArray);
      setIsEditing(false);
      setOffsetInput(selectionOffset.toString(16).toUpperCase());
      setLengthInput(selectedBytes.length.toString());
    } else {
      setEditBytes([]);
    }
  }, [selectedBytes, selectionOffset]);

  const commitContextChange = () => {
    if (!onContextChange) return;
    const off = parseInt(offsetInput, 16);
    const len = parseInt(lengthInput, 10);
    if (!isNaN(off) && !isNaN(len) && len > 0) {
      onContextChange(off, len);
    }
  };

  const activeFinding = scanResults.find(f => selectionOffset >= f.offset && selectionOffset < f.offset + f.length);
  const hasActiveResults = scanResults.some(f => !f.isDeleted && f.type !== 'DESTROYED_ARTIFACT');

  // Show button if there are active results OR if we are in a Completed/Processing state (Feedback)
  const showNeuterAll = hasActiveResults || actionStatus === 'completed' || actionStatus === 'processing' || actionStatus === 'starting';

  const handleAnalyze = async (mode: AnalysisMode) => {
    if (!selectedBytes || selectedBytes.length === 0) return;
    
    setActiveMode(mode);
    if (onModeChange) onModeChange(mode);
    
    setLoading(true);
    setResult(null);
    
    try {
      const hexString = Array.from(selectedBytes)
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join(' ');
        
      // Prepare v3.0 Context Info
      const contextInfo = activeFinding ? {
          path: activeFinding.inference?.resolvedPath || "Unknown",
          parentName: "Unknown", 
          flags: 0 
      } : undefined;

      const response = await analyzeHiveChunk(hexString, mode, selectionOffset, contextInfo);
      setResult(response);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleHexChange = (index: number, value: string) => {
    if (value.length > 2) return;
    const newBytes = [...editBytes];
    newBytes[index] = value.toUpperCase();
    setEditBytes(newBytes);
    setIsEditing(true);
  };

  const applyManualPatch = () => {
    if (!onPatchBytes) return;
    const byteArray = new Uint8Array(editBytes.map(h => parseInt(h, 16) || 0));
    onPatchBytes(selectionOffset, byteArray);
    setIsEditing(false);
    if (onModeChange) onModeChange("MANUAL_HEX_PATCH");
  };

  const applyAutoHeal = () => {
    if (!result?.autoFixHex || !onPatchBytes) return;
    
    const hex = result.autoFixHex.replace(/\s+/g, '');
    if (hex.length % 2 !== 0) return;
    
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    
    onPatchBytes(selectionOffset, bytes);
    alert("AI Auto-Heal Applied Successfully.");
    if (onModeChange) onModeChange("AI_AUTO_HEAL_APPLIED");
  };

  const applyAutoRepair = () => {
    if (!selectedBytes || !onPatchBytes) return;
    const repaired = repairKeyNode(selectedBytes);
    
    if (onModeChange) onModeChange("STRUCTURAL_REPAIR");
    
    if (repaired) {
      onPatchBytes(selectionOffset, repaired);
      alert("Key Structure successfully rebuilt (Name/Class Lengths reset).");
    } else {
      alert("Could not automatically repair this structure.\n\nReason: Signature 'nk' mismatch or insufficient length.\n\nTry manual patching in Hex View.");
    }
  };

  const severityColor = (s: string) => {
    switch(s) {
      case 'critical': return 'text-red-500 border-red-900 bg-red-950/50 shadow-[0_0_15px_rgba(220,38,38,0.2)]';
      case 'high': return 'text-orange-500 border-orange-900 bg-orange-950/50';
      case 'medium': return 'text-yellow-500 border-yellow-900 bg-yellow-950/50';
      default: return 'text-cyan-500 border-cyan-900 bg-cyan-950/50';
    }
  };

  const modes = [
    { id: AnalysisMode.ROOTKIT_HEURISTIC, label: 'Rootkit & Hook Detection', desc: 'Scan for IFEO, AppInit, and hidden driver hooks.', icon: '☣️' },
    { id: AnalysisMode.SCRIPT_GENERATION, label: 'Generate Repair Script', desc: 'Create Python/PS1 to reconstruct FUBAR hives.', icon: '📜' },
    { id: AnalysisMode.GHOST_VIRTUALIZATION, label: 'Virtualization / Ghost Keys', desc: 'Detect keys existing only in memory/containers.', icon: '👻' },
    { id: AnalysisMode.ACL_CLOAKING, label: 'ACL Cloaking / Hidden', desc: 'Find keys hidden from System/Admins.', icon: '🛡️' },
    { id: AnalysisMode.PERMISSION_BYPASS, label: 'Access Denied / Permission', desc: 'Analyze ownership and bypass checks.', icon: '🚫' },
    { id: AnalysisMode.COMPOSITE_LAYERING, label: 'Composite / Merged Keys', desc: 'Identify dynamic composite views.', icon: '🧩' },
    { id: AnalysisMode.INTEGRITY_RECOVERY, label: 'Integrity Recovery', desc: 'Fix null bytes and broken headers.', icon: '🩹' },
  ];

  return (
    <div className="h-full flex flex-col bg-gray-950 border-l border-gray-800 w-[420px] shadow-2xl z-10">
      <div className="p-5 border-b border-gray-800 bg-gray-900/50">
        <h2 className="text-lg font-bold text-cyan-400 flex items-center gap-2 tracking-wide">
           <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
           AI Engine v9.0 <span className="text-[9px] ml-auto text-purple-400 border border-purple-900 bg-purple-950 px-1 rounded shadow-[0_0_5px_rgba(168,85,247,0.5)]">SYSINTERNALS LOGIC</span>
        </h2>
        <p className="text-[10px] text-gray-500 mt-1 font-mono">AUTORUNS & DEPENDENCY ANALYSIS</p>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        
        {/* Scan Results List */}
        {scanResults.length > 0 && (
           <div className="space-y-2">
             <div className="flex items-end justify-between mb-2">
                <div className={`text-[10px] font-bold uppercase tracking-widest ${scanResults.length > 1000 ? 'text-orange-500' : 'text-cyan-500'}`}>
                   Candidates ({scanResults.length})
                </div>
                {showNeuterAll && onDeleteAll && (
                  <button 
                    onClick={(e) => { 
                        e.stopPropagation(); 
                        onDeleteAll(); 
                    }}
                    disabled={actionStatus === 'processing' || actionStatus === 'starting'}
                    className={`text-[9px] font-bold px-2 py-1 rounded uppercase border transition-all duration-300
                        ${actionStatus === 'idle' ? 'bg-red-900/20 hover:bg-red-900/40 text-red-400 border-red-900/50' : ''}
                        ${actionStatus === 'starting' || actionStatus === 'processing' ? 'bg-yellow-900/20 text-yellow-400 border-yellow-900/50 animate-pulse cursor-wait' : ''}
                        ${actionStatus === 'completed' ? 'bg-green-900/20 text-green-400 border-green-900/50' : ''}
                    `}
                  >
                    {actionStatus === 'idle' && "Neuter All Threats"}
                    {actionStatus === 'starting' && "Starting..."}
                    {actionStatus === 'processing' && "Neutering... (Processing)"}
                    {actionStatus === 'completed' && "✓ Operation Complete"}
                  </button>
                )}
             </div>
             <div className="max-h-40 overflow-y-auto border border-gray-800 rounded-lg bg-black/20">
                {/* Performance Optimization: Limit DOM nodes to first 500 to allow UI thread to breathe during massive scans */}
                {scanResults.slice(0, 500).map((finding) => (
                  <div 
                    key={finding.id}
                    onClick={() => onSelectFinding(finding)}
                    className={`p-2 border-b border-gray-800 cursor-pointer text-[10px] font-mono flex justify-between items-center
                      ${activeFinding?.id === finding.id ? 'bg-cyan-900/30 text-cyan-300' : 'text-gray-400 hover:bg-gray-900'}
                      ${finding.isDeleted ? 'line-through opacity-50' : ''}
                    `}
                  >
                    <div className="flex flex-col overflow-hidden">
                        <span className="truncate max-w-[200px] flex items-center gap-1">
                            {finding.isSystemCritical && <span title="System Critical - Protected">🛡️</span>}
                            {finding.type === 'PERSISTENCE_MECHANISM' && <span title="Sysinternals ASEP - High Risk">🔥</span>}
                            {finding.name}
                        </span>
                        {/* v8.0: Show Subkey count */}
                        {finding.subkeyCount !== undefined && finding.subkeyCount > 0 && (
                            <span className="text-[8px] text-gray-600">Children: {finding.subkeyCount}</span>
                        )}
                    </div>
                    <span className={`opacity-50 ${finding.confidence >= 1.0 || finding.type === 'PERSISTENCE_MECHANISM' ? 'text-red-400 font-bold' : ''}`}>{finding.type.substring(0,4)}</span>
                  </div>
                ))}
                {scanResults.length > 500 && (
                    <div className="p-2 text-center text-[9px] text-gray-600 italic border-t border-gray-800">
                        ... and {scanResults.length - 500} more candidates. Use Search/Filter to find specific keys.
                    </div>
                )}
             </div>
           </div>
        )}

        {/* Hex/Context Editor */}
        <div className="bg-gray-900 p-4 rounded-lg border border-gray-800 shadow-inner">
           <div className="flex justify-between items-center mb-3 border-b border-gray-800 pb-2">
             <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Context & Patching</span>
             <div className="flex gap-1">
                <input value={offsetInput} onChange={e=>setOffsetInput(e.target.value)} className="w-16 bg-black/40 border border-gray-700 text-[10px] text-cyan-300 px-1" placeholder="OFF"/>
                <input value={lengthInput} onChange={e=>setLengthInput(e.target.value)} className="w-10 bg-black/40 border border-gray-700 text-[10px] text-cyan-300 px-1" placeholder="LEN"/>
                <button onClick={() => commitContextChange()} className="px-2 bg-gray-800 text-[9px] text-gray-400 border border-gray-700 hover:text-cyan-400">GO</button>
             </div>
           </div>
           
           {selectedBytes ? (
             <div>
               <div className="grid grid-cols-8 gap-1 mb-3">
                  {editBytes.slice(0, 32).map((byteStr, idx) => (
                    <input 
                      key={idx}
                      type="text"
                      value={byteStr}
                      onChange={(e) => handleHexChange(idx, e.target.value)}
                      className={`w-full text-center text-[9px] bg-gray-800 border border-gray-700 focus:border-cyan-500 outline-none p-0.5 rounded
                        ${isEditing ? 'text-yellow-400' : 'text-gray-400'}
                      `}
                      maxLength={2}
                    />
                  ))}
                  {editBytes.length > 32 && <div className="col-span-8 text-center text-[9px] text-gray-600 italic">... {editBytes.length - 32} bytes hidden ...</div>}
               </div>

               <div className="grid grid-cols-2 gap-2">
                 {isEditing ? (
                    <button onClick={() => applyManualPatch()} className="col-span-2 py-2 bg-yellow-900/30 border border-yellow-700 text-yellow-400 text-[10px] font-bold rounded">APPLY MANUAL PATCH</button>
                 ) : (
                    <>
                       <button onClick={() => activeFinding && onDeleteFinding && onDeleteFinding(activeFinding)} className="py-2 bg-red-900/20 border border-red-900/50 text-red-400 text-[10px] font-bold rounded hover:bg-red-900/40">SAFE NEUTER</button>
                       <button onClick={() => applyAutoRepair()} className="py-2 bg-blue-900/20 border border-blue-900/50 text-blue-400 text-[10px] font-bold rounded hover:bg-blue-900/40">STRUCT REPAIR</button>
                    </>
                 )}
               </div>
             </div>
           ) : (
             <div className="text-center text-[10px] text-gray-600 py-4">
               Select a finding or byte range to enable patching.
             </div>
           )}
        </div>

        {/* v3.0 Intelligence Modules */}
        <div>
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3">AI Intelligence Modules</div>
          
          {!selectedBytes && (
            <div className="mb-3 p-2 border border-yellow-900/30 bg-yellow-900/10 rounded text-[10px] text-yellow-500 flex items-center gap-2">
               <span>⚠</span> Select a finding or hex range above to enable AI analysis.
            </div>
          )}

          <div className="grid grid-cols-1 gap-2">
            {modes.map((m) => (
              <button
                key={m.id}
                onClick={() => handleAnalyze(m.id)}
                disabled={!selectedBytes || loading}
                className={`group flex items-center gap-3 p-2.5 rounded border text-left transition-all
                  ${m.id === AnalysisMode.ROOTKIT_HEURISTIC ? 'border-red-900/30 bg-red-900/10 hover:bg-red-900/20' : 'border-gray-800 bg-gray-800/50 hover:bg-gray-800'}
                  ${loading && activeMode === m.id ? 'animate-pulse border-cyan-500/50' : ''}
                  disabled:opacity-40 disabled:cursor-not-allowed disabled:grayscale
                `}
              >
                <div className="text-xl">{m.icon}</div>
                <div>
                   <div className={`text-xs font-bold ${m.id === AnalysisMode.ROOTKIT_HEURISTIC ? 'text-red-300' : 'text-gray-300'} group-hover:text-white`}>{m.label}</div>
                   <div className="text-[9px] text-gray-500">{m.desc}</div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* AI Analysis Result */}
        {result && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 pt-2">
            <div className={`p-4 rounded-lg border ${severityColor(result.severity)} mb-3`}>
               <div className="flex justify-between items-start mb-2">
                  <h3 className="font-bold text-xs uppercase">{result.title}</h3>
                  <span className="text-[9px] font-black uppercase px-1.5 py-0.5 rounded bg-black/30">{result.severity}</span>
               </div>
               <p className="text-[11px] opacity-90 leading-relaxed mb-3">{result.description}</p>
               
               {/* Auto-Fix Button (v3.0 Feature) */}
               {result.autoFixHex && (
                  <button 
                    onClick={() => applyAutoHeal()}
                    className="w-full py-2 bg-cyan-400/10 hover:bg-cyan-400/20 border border-cyan-400/50 text-cyan-300 text-[10px] font-bold rounded uppercase flex items-center justify-center gap-2 mb-2"
                  >
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                    AI Auto-Heal (Apply Fix)
                  </button>
               )}

               {/* Generated Script View (v3.0 Feature) */}
               {result.generatedScript && (
                  <div className="mt-2">
                     <div className="text-[9px] font-bold text-gray-500 uppercase mb-1">Generated Reconstruction Script</div>
                     <textarea 
                       readOnly 
                       className="w-full h-24 bg-black/50 border border-gray-700 text-[9px] font-mono text-green-400 p-2 rounded resize-none focus:outline-none"
                       value={result.generatedScript}
                     />
                     <button 
                       onClick={() => navigator.clipboard.writeText(result.generatedScript || "")}
                       className="w-full mt-1 py-1 bg-gray-800 hover:bg-gray-700 text-gray-400 text-[9px] rounded border border-gray-700"
                     >
                       Copy Script to Clipboard
                     </button>
                  </div>
               )}

               {!result.generatedScript && (
                 <div className="bg-black/20 p-2 rounded border border-gray-800/50 mt-2">
                   <h4 className="text-[9px] text-gray-500 uppercase mb-1">Technical Details</h4>
                   <p className="text-[10px] text-cyan-100/70 font-mono">{result.technicalDetails}</p>
                 </div>
               )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
});

export default AnalysisPanel;