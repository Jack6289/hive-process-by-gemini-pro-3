
import { GoogleGenAI } from "@google/genai";
import { AnalysisMode, AnalysisResult } from '../types';

const getClient = () => new GoogleGenAI({ apiKey: process.env.API_KEY });

// v3.1: Enhanced System Prompt with Binary Rootkit Context
const SYSTEM_PROMPT = `
You are HiveMind AI v3.1, an advanced Offensive Security & Forensics Engine specialized in Windows Registry internals.
You process raw binary data from Registry Hives (NTUSER.DAT, SYSTEM, SAM, SOFTWARE).

YOUR CAPABILITIES:
1. **Rootkit Detection**: You recognize binary patterns like Null-terminator hiding (embedded 0x00), Unlinked DKOM keys, and Class Data Injection.
2. **Malware Heuristics**: You recognize persistence hooks (AppInit_DLLs, IFEO, COM Hijacks, Service Replacement).
3. **Auto-Healing**: You can generate raw hex patches to neutralize threats (e.g., nop-out malicious values, restore standard ACLs, clear Class Data).
4. **Script Generation**: For irreparable damage, you generate Python/PowerShell scripts to reconstruct the hive.

OUTPUT FORMAT:
Always return valid JSON.
- If a threat is found, provide 'autoFixHex' (a hex string of the corrected bytes).
- If 'SCRIPT_GENERATION' mode is active, you MUST provide the 'generatedScript' field containing the code block.
- Strictly escape backslashes in paths (e.g., "C:\\\\Windows").
`;

const cleanJson = (text: string): string => {
    // Remove Markdown blocks and any leading/trailing whitespace
    return text.replace(/^```json\s*/g, "").replace(/\s*```$/g, "").trim();
};

export const analyzeHiveChunk = async (
  hexString: string, 
  mode: AnalysisMode, 
  offset: number,
  contextInfo?: { path: string, parentName: string, flags: number, findingType?: string }
): Promise<AnalysisResult> => {
  const ai = getClient();
  
  let problemStatement = "";
  const contextStr = contextInfo ? `PATH: ${contextInfo.path}\nFLAGS: 0x${contextInfo.flags.toString(16)}\nFINDING_TYPE: ${contextInfo.findingType || 'N/A'}` : "PATH: Unknown";

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
    
    // --- v3.1 UPDATED ENGINES ---
    case AnalysisMode.ROOTKIT_HEURISTIC:
      problemStatement = `
        TASK: ROOTKIT & MALWARE ANALYSIS (v3.1 Active Mode).
        - Context: ${contextStr}
        
        SPECIFIC HANDLING:
        1. **NULL_EMBEDDED**: The scanner detected 0x00 inside the key name. This hides the suffix from Windows API.
           - HEALING: Provide 'autoFixHex' replacing the embedded nulls with '_' (0x5F).
           
        2. **CLASS_INJECTION**: The scanner detected suspicious Class Data (offset 0x4A len > 0).
           - Analyze the hex for potential shellcode (0x90 sleds, 0xCC int3, shellcode patterns).
           - HEALING: Provide 'autoFixHex' setting Class Length (offset 0x4A) to 0 and Class Offset (0x30) to -1 (0xFFFFFFFF).

        3. **UNLINKED_DKOM**: The key is unlinked from the tree.
           - Analyze if this is a legitimate deleted remnant or active DKOM.
           - If malicious, recommend SAFE NEUTER (zeroing pointers).

        4. **General Malware**: Check for IFEO, AppInit_DLLs, COM Hijacks.
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
        - CRITICAL: Return the script in the 'generatedScript' JSON field.
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
      "generatedScript": "Optional: Code block string if script generation was requested"
    }
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash', 
      contents: fullPrompt,
      config: {
        responseMimeType: "application/json",
        systemInstruction: SYSTEM_PROMPT
      }
    });

    const text = response.text || "";
    // Robust sanitization
    const sanitized = cleanJson(text);
    
    // Handle potential escape issues in generated code
    // We use a simplified parse but wrapped in try/catch
    try {
        return JSON.parse(sanitized) as AnalysisResult;
    } catch (parseError) {
        // If JSON parse fails, it might be due to newlines in the script string. 
        // We attempt to rescue it or return a formatted error.
        console.error("JSON Parse Error on AI response:", parseError);
        return {
            title: "AI Processing Error",
            description: "The AI generated a script but the JSON format was invalid.",
            severity: "medium",
            technicalDetails: "JSON Syntax Error",
            recommendation: "Try again.",
            generatedScript: "# Error parsing script from AI response.\n# Raw text: \n" + text
        };
    }
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
