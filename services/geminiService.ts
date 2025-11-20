import { GoogleGenAI } from "@google/genai";
import { AnalysisMode, AnalysisResult } from '../types';

const getClient = () => new GoogleGenAI({ apiKey: process.env.API_KEY });

// v3.0: Enhanced System Prompt with "Threat Intelligence"
const SYSTEM_PROMPT = `
You are HiveMind AI v3.0, an advanced Offensive Security & Forensics Engine specialized in Windows Registry internals.
You process raw binary data from Registry Hives (NTUSER.DAT, SYSTEM, SAM, SOFTWARE).

YOUR CAPABILITIES:
1. **Rootkit Detection**: You know the patterns of rootkits (e.g., Null-terminator hiding, Unlinked keys, DKOM hidden keys).
2. **Malware Heuristics**: You recognize persistence hooks (AppInit_DLLs, IFEO, COM Hijacks, Service Replacement).
3. **Auto-Healing**: You can generate raw hex patches to neutralize threats (e.g., nop-out malicious values, restore standard ACLs).
4. **Script Generation**: For irreparable damage, you generate Python (using python-registry) or PowerShell scripts to reconstruct the hive.

OUTPUT FORMAT:
Always return valid JSON.
- If a threat is found, provide 'autoFixHex' (a hex string of the corrected bytes).
- If 'SCRIPT_GENERATION' mode is active, provide 'generatedScript' containing the code.
- Strictly escape backslashes in paths (e.g., "C:\\\\Windows").
`;

export const analyzeHiveChunk = async (
  hexString: string, 
  mode: AnalysisMode, 
  offset: number,
  contextInfo?: { path: string, parentName: string, flags: number }
): Promise<AnalysisResult> => {
  const ai = getClient();
  
  let problemStatement = "";
  const contextStr = contextInfo ? `PATH: ${contextInfo.path}\nFLAGS: 0x${contextInfo.flags.toString(16)}` : "PATH: Unknown";

  switch (mode) {
    case AnalysisMode.GHOST_VIRTUALIZATION:
      problemStatement = `
        TASK: Detect "Ghost Keys".
        - Analyze 'nk' flags at offset 0x02.
        - Look for Flag 0x10 (Hive Entry) or 0x20 (SymLink) in unexpected locations.
        - If confirmed, suggest a patch to clear the virtualization flag.
      `;
      break;
    case AnalysisMode.ACL_CLOAKING:
      problemStatement = `
        TASK: Detect "ACL Hiding" (Rootkit Technique).
        - Analyze 'sk' cell. Look for NULL DACL or DENY ACEs for SYSTEM/Admin.
        - HEALING: Provide 'autoFixHex' to replace the Security Cell Index (offset 0x2C in nk) with 0xFFFFFFFF (inherit parent) or a known safe index.
      `;
      break;
    case AnalysisMode.PERMISSION_BYPASS:
      problemStatement = `
        TASK: Analyze Permission Structure.
        - User has Access Denied. Check Owner SID.
        - HEALING: Suggest hex patch to reset ownership.
      `;
      break;
    case AnalysisMode.COMPOSITE_LAYERING:
      problemStatement = `
        TASK: Analyze Composite/Merged Keys.
        - Check Timestamp (0x04) for future dates or 0 values.
        - Check if parent key predates child significantly (impossible in standard write).
      `;
      break;
    case AnalysisMode.INTEGRITY_RECOVERY:
      problemStatement = `
        TASK: Fix Corruption / Illegal Characters.
        - Check Name Length (0x48) vs actual bytes.
        - HEALING: Provide 'autoFixHex' that corrects the Name Length field or replaces null bytes in the name with underscores.
      `;
      break;
    
    // --- v3.0 NEW ENGINES ---
    case AnalysisMode.ROOTKIT_HEURISTIC:
      problemStatement = `
        TASK: ROOTKIT & MALWARE PATTERN MATCHING.
        - Context: ${contextStr}
        - Analyze the binary for specific hooking techniques:
          1. **Image File Execution Options (IFEO)**: Debugger attachment hooks.
          2. **AppInit_DLLs**: DLL injection via User32.dll.
          3. **Legacy Filter Drivers**: UpperFilters/LowerFilters in ControlSet services.
          4. **COM Hijacking**: CLSID pointing to user-writable locations.
        - Check for "Null-Byte Hiding" in the Key Name (inserting 0x00 mid-string).
        - IF MALICIOUS: Set severity to 'critical'. Provide 'autoFixHex' to zero out the Value List offset (0x28) to detach the malware payload.
      `;
      break;

    case AnalysisMode.SCRIPT_GENERATION:
      problemStatement = `
        TASK: GENERATE RECONSTRUCTION SCRIPT.
        - The Registry Hive structure at this offset is FUBAR (Beyond Repair).
        - Generate a Python script using 'python-registry' or standard struct parsing.
        - The script should:
          1. Open the hive file.
          2. Seek to offset 0x${offset.toString(16)}.
          3. Extract the raw key name and timestamp.
          4. Create a new clean hive file and export this key's children recursively to it.
        - Put the code in the 'generatedScript' JSON field.
      `;
      break;
  }

  const fullPrompt = `
    ${problemStatement}
    
    INPUT DATA:
    - Offset: 0x${offset.toString(16)}
    - Hex: ${hexString}
    
    RETURN JSON ONLY:
    {
      "title": "Analysis Title",
      "description": "Summary",
      "severity": "low" | "medium" | "high" | "critical",
      "technicalDetails": "Deep dive",
      "recommendation": "Action",
      "autoFixHex": "Optional: Continuous hex string of the FIXED version of the input data (same length)",
      "generatedScript": "Optional: Code block for script mode"
    }
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash', // Using Flash for speed in analysis loop
      contents: fullPrompt,
      config: {
        responseMimeType: "application/json",
        systemInstruction: SYSTEM_PROMPT
      }
    });

    let text = response.text;
    if (!text) throw new Error("No response from AI");
    
    // Cleanup
    text = text.replace(/^```json\s*/g, "").replace(/\s*```$/g, "").trim();
    
    // Escape fix for paths
    const fixedText = text.replace(/\\(?![/\\bfnrtu"])/g, "\\\\");

    return JSON.parse(fixedText) as AnalysisResult;
  } catch (error) {
    console.error("Gemini Engine Error:", error);
    return {
      title: "AI Engine Fault",
      description: "The neural engine could not process this sector.",
      severity: "low",
      technicalDetails: String(error),
      recommendation: "Retry analysis."
    };
  }
};