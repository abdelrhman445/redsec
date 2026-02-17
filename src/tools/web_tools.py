import socket
import requests
from typing import Type
from crewai_tools import BaseTool
from pydantic import BaseModel, Field

# =====================================================
# 🔧 Helper
# =====================================================
def extract_target(kwargs):
    return (
        kwargs.get("target") or kwargs.get("target_url") or kwargs.get("url") or 
        kwargs.get("domain") or kwargs.get("host") or kwargs.get("base_url")
    )

# =====================================================
# 1. Port Scanner
# =====================================================
class PortScanInput(BaseModel):
    target: str = Field(..., description="Target domain/IP.")
    ports: str = Field(None, description="Optional ports list.")

class PortScannerTool(BaseTool):
    name: str = "Basic Port Scanner"
    description: str = "Scans target for open ports."
    args_schema: Type[BaseModel] = PortScanInput

    def _run(self, **kwargs) -> str:
        target = extract_target(kwargs)
        if not target: return "Error: No target."
        try:
            ip = socket.gethostbyname(target)
        except:
            return f"Could not resolve {target}"

        ports = [21, 22, 80, 443, 3306]
        open_ports = []
        for p in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            sock.close()
        return f"Target: {target} ({ip})\nOpen Ports: {open_ports if open_ports else 'None'}"

# =====================================================
# 2. Robots & Headers & Dirs
# =====================================================
class WebInput(BaseModel):
    target: str = Field(..., description="Target URL.")

class RobotsTxtTool(BaseTool):
    name: str = "Robots.txt Inspector"
    description: str = "Reads robots.txt file."
    args_schema: Type[BaseModel] = WebInput

    def _run(self, **kwargs) -> str:
        target = extract_target(kwargs)
        if not target.startswith("http"): target = f"http://{target}"
        try:
            r = requests.get(f"{target}/robots.txt", timeout=5, headers={'User-Agent': 'RedSec'})
            return f"Status: {r.status_code}\nContent:\n{r.text[:500]}" if r.status_code == 200 else "Not found."
        except Exception as e: return str(e)

class SecurityHeadersTool(BaseTool):
    name: str = "Security Headers Check"
    description: str = "Checks for missing security headers."
    args_schema: Type[BaseModel] = WebInput

    def _run(self, **kwargs) -> str:
        target = extract_target(kwargs)
        if not target.startswith("http"): target = f"http://{target}"
        try:
            headers = requests.get(target, timeout=5).headers
            required = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
            missing = [h for h in required if h not in headers]
            return f"Missing Headers: {missing if missing else 'None (Secure!)'}"
        except Exception as e: return str(e)

class DirectorySearchTool(BaseTool):
    name: str = "Directory Brute Force"
    description: str = "Checks common paths (/admin, /login)."
    args_schema: Type[BaseModel] = WebInput

    def _run(self, **kwargs) -> str:
        base = extract_target(kwargs)
        if not base.startswith("http"): base = f"http://{base}"
        found = []
        for path in ["admin", "login", "dashboard", "config", "api"]:
            try:
                if requests.get(f"{base}/{path}", timeout=3).status_code in [200, 403]:
                    found.append(path)
            except: pass
        return f"Found Paths: {found if found else 'None'}"

# =====================================================
# 3. CVE Lookup
# =====================================================
class CVEInput(BaseModel):
    technology: str = Field(..., description="Tech stack name.")

class CVESearchTool(BaseTool):
    name: str = "CVE Lookup"
    description: str = "Simulates searching for vulnerabilities."
    args_schema: Type[BaseModel] = CVEInput

    def _run(self, **kwargs) -> str:
        tech = kwargs.get("technology")
        return f"🔎 Vulnerabilities for {tech}:\n- Check for RCE if outdated.\n- Check default creds.\n- Verify CVE database."