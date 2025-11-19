
import React, { useMemo, useState, useEffect, useRef } from 'react';

interface HexViewerProps {
  data: Uint8Array;
  baseOffset: number;
  onSelectionChange: (start: number, end: number) => void;
}

const BYTES_PER_ROW = 16;
const PAGE_SIZE = 1024; // View 1KB at a time for performance

const HexViewer: React.FC<HexViewerProps> = ({ data, baseOffset, onSelectionChange }) => {
  const [page, setPage] = useState(0);
  const [selection, setSelection] = useState<{ start: number | null; end: number | null }>({ start: null, end: null });
  const prevDataLengthRef = useRef<number>(data.length);

  const totalPages = Math.ceil(data.length / PAGE_SIZE);
  const pageData = useMemo(() => {
    const start = page * PAGE_SIZE;
    const end = Math.min(start + PAGE_SIZE, data.length);
    return data.slice(start, end);
  }, [data, page]);

  const handleByteClick = (index: number) => {
    const absoluteIndex = (page * PAGE_SIZE) + index;
    
    if (selection.start === null || (selection.start !== null && selection.end !== null)) {
      // New selection
      setSelection({ start: absoluteIndex, end: absoluteIndex });
      onSelectionChange(absoluteIndex, absoluteIndex);
    } else {
      // Extend selection
      const newStart = Math.min(selection.start, absoluteIndex);
      const newEnd = Math.max(selection.start, absoluteIndex);
      setSelection({ start: newStart, end: newEnd });
      onSelectionChange(newStart, newEnd);
    }
  };

  const renderRows = () => {
    const rows = [];
    for (let i = 0; i < pageData.length; i += BYTES_PER_ROW) {
      const rowOffset = (page * PAGE_SIZE) + i + baseOffset;
      const rowBytes = pageData.slice(i, i + BYTES_PER_ROW);
      
      const hexSpans = [];
      const asciiSpans = [];

      for (let j = 0; j < BYTES_PER_ROW; j++) {
        if (j < rowBytes.length) {
          const byteVal = rowBytes[j];
          const absoluteIndex = (page * PAGE_SIZE) + i + j;
          const isSelected = selection.start !== null && selection.end !== null && absoluteIndex >= selection.start && absoluteIndex <= selection.end;

          hexSpans.push(
            <span
              key={`hex-${j}`}
              onClick={() => handleByteClick(i + j)}
              className={`inline-block w-6 text-center cursor-pointer hover:bg-cyan-900 ${isSelected ? 'bg-cyan-600 text-white font-bold' : 'text-gray-300'}`}
            >
              {byteVal.toString(16).padStart(2, '0').toUpperCase()}
            </span>
          );

          // Simple ASCII char or dot
          const char = (byteVal >= 32 && byteVal <= 126) ? String.fromCharCode(byteVal) : '.';
          asciiSpans.push(
            <span key={`ascii-${j}`} className={`inline-block w-[1ch] text-center ${isSelected ? 'text-cyan-400 font-bold' : 'text-gray-500'}`}>
              {char}
            </span>
          );
        } else {
          hexSpans.push(<span key={`hex-${j}`} className="inline-block w-6"></span>);
          asciiSpans.push(<span key={`ascii-${j}`} className="inline-block w-[1ch]"></span>);
        }
      }

      rows.push(
        <div key={rowOffset} className="flex font-mono text-sm leading-relaxed hover:bg-gray-900">
          {/* Offset Column */}
          <div className="w-24 text-cyan-700 select-none border-r border-gray-800 mr-4">
            {rowOffset.toString(16).padStart(8, '0').toUpperCase()}
          </div>
          
          {/* Hex Column */}
          <div className="flex gap-2 mr-4">
             <div className="flex gap-1">{hexSpans.slice(0, 8)}</div>
             <div className="flex gap-1">{hexSpans.slice(8, 16)}</div>
          </div>

          {/* ASCII Column */}
          <div className="border-l border-gray-800 pl-4 text-gray-400 opacity-80">
            {asciiSpans}
          </div>
        </div>
      );
    }
    return rows;
  };

  useEffect(() => {
      // Only reset if length changes significantly (e.g. new file loaded)
      // Patches usually keep length or expand slightly, but user likely wants to keep context.
      if (data.length !== prevDataLengthRef.current) {
          setPage(0);
          setSelection({ start: null, end: null });
          prevDataLengthRef.current = data.length;
      }
  }, [data]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex justify-between items-center bg-gray-900 px-4 py-2 border-b border-gray-800 text-xs">
         <div className="text-gray-400">
           Showing {page * PAGE_SIZE} - {Math.min((page + 1) * PAGE_SIZE, data.length)} of {data.length} bytes
         </div>
         <div className="flex gap-2">
           <button 
             onClick={() => setPage(Math.max(0, page - 1))}
             disabled={page === 0}
             className="px-2 py-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded text-cyan-400"
           >
             &lt; Prev
           </button>
           <button 
             onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
             disabled={page === totalPages - 1}
             className="px-2 py-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded text-cyan-400"
           >
             Next &gt;
           </button>
         </div>
      </div>
      <div className="flex-1 overflow-auto p-4 bg-gray-950">
        {renderRows()}
      </div>
    </div>
  );
};

export default HexViewer;
