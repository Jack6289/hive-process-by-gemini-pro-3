
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
  autoFixHex?: string; // New: Hex string for automatic patching
  generatedScript?: string; // New: Python/PowerShell script for reconstruction
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
  type: 'VIRTUALIZED' | 'STUBBORN' | 'CORRUPT' | 'HIDDEN' | 'SEARCH_MATCH' | 'COMPOSITE' | 'RECOVERED_KEY' | 'DATA_REMNANT' | 'DESTROYED_ARTIFACT' | 'ROOTKIT_NULL_EMBEDDED' | 'ROOTKIT_CLASS_INJECTION' | 'ROOTKIT_UNLINKED_DKOM' | 'PERSISTENCE_MECHANISM';
  name: string;
  description: string;
  confidence: number;
  isDeleted?: boolean;
  allocationStatus?: 'Allocated' | 'Free' | 'Unknown';
  binRelativeOffset?: number;
  inference?: InferenceInsight;
  // v8.0 Safety Fields
  isSystemCritical?: boolean;
  subkeyCount?: number;
  // v9.0 Association Fields
  associatedOffsets?: number[]; // Offsets of related keys (e.g. Service -> Enum)
}

export enum AnalysisMode {
  GHOST_VIRTUALIZATION = 'GHOST_VIRTUALIZATION', 
  ACL_CLOAKING = 'ACL_CLOAKING',                 
  PERMISSION_BYPASS = 'PERMISSION_BYPASS',       
  COMPOSITE_LAYERING = 'COMPOSITE_LAYERING',     
  INTEGRITY_RECOVERY = 'INTEGRITY_RECOVERY',
  ROOTKIT_HEURISTIC = 'ROOTKIT_HEURISTIC',       // v3.0/v3.1: Active Engine
  SCRIPT_GENERATION = 'SCRIPT_GENERATION'        // v3.0: New Engine
}