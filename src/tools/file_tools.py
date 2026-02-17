import os
import subprocess
import json
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

# ==================================
# 1️⃣ CODE READER TOOL
# ==================================
class ReadCodeInput(BaseModel):
    file_path: str = Field(..., description="Path to the code file")

class CodeReaderTool(BaseTool):  # 🔥 الاسم المعتمد
    name: str = "Read Code File"
    description: str = "Reads a source code file from disk and returns its content."
    args_schema: type = ReadCodeInput

    def _run(self, file_path: str) -> str:
        if not os.path.exists(file_path):
            return f"❌ File not found: {file_path}"
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e: return str(e)

# ==================================
# 2️⃣ SAST TOOL (Bandit)
# ==================================
class SASTTool(BaseTool):
    name: str = "SAST Scanner (Bandit)"
    description: str = "Runs static analysis on Python code to find security flaws. Input is file path."
    args_schema: type = ReadCodeInput

    def _run(self, file_path: str) -> str:
        if not file_path.endswith(".py"):
            return "⚠️ SAST Tool currently supports Python files only."
            
        try:
            cmd = ["bandit", "-r", file_path, "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            try:
                data = json.loads(result.stdout)
                results = data.get("results", [])
                
                if not results:
                    return "✅ Bandit Analysis: No high-severity issues found."
                
                report = ["🚨 Bandit Findings:"]
                for issue in results:
                    if issue['issue_severity'] in ['HIGH', 'MEDIUM']:
                        report.append(f"- [{issue['issue_severity']}] {issue['issue_text']} (Line {issue['line_number']})")
                
                return "\n".join(report) if len(report) > 1 else "✅ Bandit: Code looks safe."
                
            except:
                return f"❌ Failed to parse Bandit output: {result.stdout}"

        except Exception as e:
            return f"❌ SAST execution error: {str(e)}"