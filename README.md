# HiveMind Forensics v2.4

**Advanced Windows Registry Binary Analysis Tool powered by Gemini AI**

HiveMind Forensics is a specialized, browser-based forensic tool designed to analyze Windows Registry Hive files (`NTUSER.DAT`, `SYSTEM`, `SAM`, `SOFTWARE`) at the raw binary level. Unlike standard registry editors, HiveMind processes the file structure directly, allowing it to detect deleted keys, virtualized "ghost" keys, and hidden ACL cloaking mechanisms.

**Current Version:** v2.4 (Safe Replay & Structural Healing)

## 🚀 Key Features

### 🧠 1. AI-Powered Forensic Analysis
Integrates **Google Gemini 2.5 Flash** to interpret raw binary anomalies.
- **Ghost Key Detection**: Identifies keys that exist in memory/containers but are flagged as virtual in the binary.
- **ACL Cloaking**: Detects keys hidden from administrators via Null DACLs or explicit DENY ACEs.
- **Corruption Recovery**: Analyzes malformed headers to recover data from corrupted hives.

### 🔄 2. Safe Transaction Log Replay (v2.4 Enhanced)
The Windows Kernel uses a Write-Ahead Log (`.LOG1`, `.LOG2`) system.
- **Physical Page Replay**: New "Safe Mode" engine that enforces 4KB page alignment during log application.
- **Anti-Crash Logic**: Automatically detects and skips garbage data or unaligned blocks that typically crash Regedit.
- **Exact Expansion**: Precisely calculates file expansion to prevent "ghost" zero-filled regions.

### 🛠️ 3. Structural Auto-Repair
- **Header Healing**: Automatically detects and fixes corrupted `nk` (Key Node) headers, restoring correct name lengths and clearing invalid class data.
- **Structure Walking**: The new "Hive Integrity Walker" scans the file before download, automatically truncating corrupt tail data or padding incomplete bins to ensure structural validity.

### 🔍 4. Heuristic Inference Engine
A deterministic graph traversal engine that reconstructs the registry tree from raw cell indexes.
- **Path Resolution**: Rebuilds full paths (e.g., `\WOW6432Node\Siemens`) even if parent links are damaged.
- **Deep Search**: "Partial Match" support for finding keys when the hierarchy is broken.
- **Raw String Scraping**: Scrapes unallocated space for "Data Remnants" (deleted keys).

### ⚡ 5. Binary Patching & Hex Editor
- **Hex Editor**: Manually edit raw bytes in the browser memory.
- **Signature Destruction**: Intentionally patch the `nk` signature of stubborn malware keys to render them inert.

## 📦 Installation & Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/HiveMind-Forensics.git
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up your API Key:
   - Create a `.env` file in the root.
   - Add: `API_KEY=your_google_gemini_api_key`
4. Run the app:
   ```bash
   npm start
   ```

## 🛡️ Forensics Methodology

HiveMind treats the file as a raw `Uint8Array`. It parses:
- **Base Block (`regf`)**
- **Hive Bins (`hbin`)**
- **Key Nodes (`nk`)**
- **Data Cells**

It does not use the Windows API, ensuring that rootkits or OS-level hooks cannot hide data from the analyzer.

## License

MIT