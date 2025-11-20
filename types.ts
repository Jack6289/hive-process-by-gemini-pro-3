
export enum HiveNodeType {
  ROOT = 'ROOT',
  KEY = 'KEY',
  VALUE = 'VALUE',
  UNKNOWN = 'UNKNOWN'
}

export interface HexSelection {
  start: number;
  end: number;
  bytes: Uint8Array;
}

export interface AnalysisResult {
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  technicalDetails: string;
  recommendation: string;
  offsetDetected?: string;
  autoFixHex?: string; // Hex string for automatic patching
  generatedScript?: string; // Python/PowerShell script for reconstruction
}

export interface InferenceInsight {
  resolvedPath: string;
  pathConfidence: number; // 0.0 - 1.0
  heuristicWarnings: string[];
  parentCellIndex: number;
  traceSteps: string[];
}

export interface ScanFinding {
  id: string;
  offset: number;
  length: number;
  type: 'VIRTUALIZED' | 'STUBBORN' | 'CORRUPT' | 'HIDDEN' | 'SEARCH_MATCH' | 'COMPOSITE' | 'RECOVERED_KEY' | 'DATA_REMNANT' | 'DESTROYED_ARTIFACT' | 'ROOTKIT_HOOK';
  name: string;
  description: string;
  confidence: number;
  isDeleted?: boolean;
  allocationStatus?: 'Allocated' | 'Free' | 'Unknown';
  binRelativeOffset?: number;
  inference?: InferenceInsight;
}

export enum AnalysisMode {
  GHOST_VIRTUALIZATION = 'GHOST_VIRTUALIZATION', 
  ACL_CLOAKING = 'ACL_CLOAKING',                 
  PERMISSION_BYPASS = 'PERMISSION_BYPASS',       
  COMPOSITE_LAYERING = 'COMPOSITE_LAYERING',     
  INTEGRITY_RECOVERY = 'INTEGRITY_RECOVERY',
  ROOTKIT_HEURISTIC = 'ROOTKIT_HEURISTIC',       // New: v3.0
  SCRIPT_GENERATION = 'SCRIPT_GENERATION'        // New: v3.0
}