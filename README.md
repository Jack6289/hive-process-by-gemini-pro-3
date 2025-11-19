# HiveMind Forensics v2.2

**Advanced Windows Registry Binary Analysis Tool powered by Gemini AI**

HiveMind Forensics is a specialized, browser-based forensic tool designed to analyze Windows Registry Hive files (`NTUSER.DAT`, `SYSTEM`, `SAM`, `SOFTWARE`) at the raw binary level. Unlike standard registry editors, HiveMind processes the file structure directly, allowing it to detect deleted keys, virtualized "ghost" keys, and hidden ACL cloaking mechanisms.

**Current Version:** v2.2 (Log Reconciliation Update)

## 🚀 Key Features

### 🧠 1. AI-Powered Forensic Analysis
Integrates **Google Gemini 2.5 Flash** to interpret raw binary anomalies.
- **Ghost Key Detection**: Identifies keys that exist in memory/containers but are flagged as virtual in the binary.
- **ACL Cloaking**: Detects keys hidden from administrators via Null DACLs or explicit DENY ACEs.
- **Corruption Recovery**: Analyzes malformed headers to recover data from corrupted hives.

### 🔍 2. Heuristic Inference Engine (No Training Required)
A deterministic graph traversal engine that reconstructs the registry tree from raw cell indexes.
- **Path Resolution**: Rebuilds full paths (e.g., `\WOW6432Node\Siemens`) even if parent links are damaged.
- **Deep Search**: "Partial Match" support for finding keys when the hierarchy is broken.
- **Raw String Scraping**: Scrapes unallocated space for "Data Remnants" (deleted keys) and "Stubborn Keys" (null-byte names).

### 🔄 3. Transaction Log Reconciliation (New in v2.2)
The Windows Kernel uses a Write-Ahead Log (`.LOG1`, `.LOG2`) system. Static analysis of `.DAT` files often yields outdated data.
- **Log Replay**: Upload `.LOG` files alongside the main hive.
- **Dirty Page Patching**: The engine applies log pages to the main memory buffer, recovering the *exact* state of the registry at the time of capture.
- **Visual Feedback**: Identify which memory pages were patched by the transaction logs.

### 🛠️ 4. Binary Patching & Repair
- **Signature Destruction**: Intentionally patch the `nk` signature of stubborn malware keys to render them inert.
- **Hex Viewer**: Low-level inspection of hive bins and cells.

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
