import requests
import socket
import os
import shodan
import re
from typing import Type, Optional
from langchain.tools import BaseTool
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# =====================================================
# 🔧 HELPER FUNCTIONS (ROBUST VERSION)
# =====================================================

def extract_target_ip(kwargs):
    """
    Shodan needs an IP. This resolves domains to IPs.
    """
    target = (
        kwargs.get("target") or 
        kwargs.get("target_url") or 
        kwargs.get("url") or 
        kwargs.get("domain") or 
        kwargs.get("host") or 
        kwargs.get("ip") or 
        kwargs.get("query")
    )
    
    if target:
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            return socket.gethostbyname(clean_target)
        except socket.gaierror:
            return clean_target
    return None

def extract_url(kwargs):
    """
    Ensures we have a valid URL (http/https) for web scanning.
    """
    target = (
        kwargs.get("target") or kwargs.get("target_url") or kwargs.get("url") or 
        kwargs.get("domain") or kwargs.get("host") or kwargs.get("query")
    )
    if not target:
        return None
    
    if target.startswith("http"):
        return target
    return f"http://{target}"

def extract_domain(kwargs):
    """
    Extracts pure domain name for Subdomain enumeration.
    """
    target = (
        kwargs.get("target") or kwargs.get("target_url") or kwargs.get("url") or 
        kwargs.get("domain") or kwargs.get("host") or kwargs.get("query")
    )
    if target:
        return target.replace("https://", "").replace("http://", "").split("/")[0]
    return None

# =====================================================
# 1️⃣ SUBDOMAIN ENUMERATION (Enhanced with Fallback)
# =====================================================

class SubdomainInput(BaseModel):
    domain: Optional[str] = Field(None, description="Target Domain.")
    target: Optional[str] = Field(None, description="Target Domain (Alternative).")
    host: Optional[str] = Field(None, description="Target Host (Alternative).")
    url: Optional[str] = Field(None, description="Target URL (Alternative).")

class SubdomainTool(BaseTool):
    name: str = "Subdomain Finder"
    description: str = "Uses crt.sh and HackerTarget to find subdomains passively."
    args_schema: Type[BaseModel] = SubdomainInput

    def _run(self, **kwargs) -> str:
        domain = extract_domain(kwargs)
        if not domain: return "❌ No domain provided. Please use key 'target' or 'domain'."

        # 1. المحاولة الأولى: crt.sh (المصدر الأساسي)
        try:
            print(f"🌐 Trying crt.sh for {domain}...")
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            # 🔥 زيادة الوقت لـ 45 ثانية للأهداف الكبيرة مثل Tesla
            r = requests.get(url, timeout=45)
            
            if r.status_code == 200:
                data = r.json()
                subdomains = set()
                for entry in data:
                    name_value = entry['name_value']
                    for sub in name_value.split('\n'):
                        if "*" not in sub:
                            subdomains.add(sub)
                
                results = list(subdomains)[:30]
                return f"🌐 (Source: crt.sh) Found {len(subdomains)} subdomains. Top results:\n" + "\n".join(results)
        
        except Exception as e:
            print(f"⚠️ crt.sh failed/timed out: {e}")

        # 2. المحاولة الثانية: HackerTarget (البديل السريع)
        try:
            print(f"🌐 Switching to HackerTarget for {domain}...")
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            r = requests.get(url, timeout=20)
            
            if r.status_code == 200:
                lines = r.text.split("\n")
                subdomains = set()
                for line in lines:
                    parts = line.split(",")
                    if len(parts) > 0:
                        subdomains.add(parts[0])
                
                results = list(subdomains)[:30]
                if not results:
                    return f"✅ No subdomains found via APIs for {domain}."
                    
                return f"🌐 (Source: HackerTarget) Found {len(subdomains)} subdomains. Top results:\n" + "\n".join(results)

        except Exception as e:
            return f"❌ All Subdomain APIs failed. Error: {str(e)}"

        return f"❌ Could not fetch subdomains for {domain}."

# =====================================================
# 2️⃣ JS SECRET SCANNER
# =====================================================

class JSScanInput(BaseModel):
    url: Optional[str] = Field(None, description="Target URL.")
    target: Optional[str] = Field(None, description="Target.")
    host: Optional[str] = Field(None, description="Target Host.")

class JSSensitiveTool(BaseTool):
    name: str = "JS Secret Scanner"
    description: str = "Extracts .js files from page and searches for secrets (API Keys, AWS)."
    args_schema: Type[BaseModel] = JSScanInput

    def _run(self, **kwargs) -> str:
        url = extract_url(kwargs)
        if not url: return "❌ No URL provided."

        findings = []
        try:
            # 1. Get Main Page
            r = requests.get(url, timeout=10, verify=False)
            html = r.text
            
            # 2. Extract JS Links
            scripts = re.findall(r'<script src="([^"]+)"', html)
            full_links = []
            for s in scripts:
                if s.startswith("http"): full_links.append(s)
                else: full_links.append(f"{url.rstrip('/')}/{s.lstrip('/')}")

            findings.append(f"🔍 Found {len(full_links)} JS files linked.")

            # 3. Scan each JS file
            patterns = {
                "AWS Key": r"AKIA[0-9A-Z]{16}",
                "Generic API Key": r"(api_key|apikey|access_token)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{20,})",
                "Bearer Token": r"Bearer [a-zA-Z0-9_\-\.]+",
                "Google Key": r"AIza[0-9A-Za-z-_]{35}"
            }

            # Scan first 6 files only for speed
            for js_link in full_links[:6]: 
                try:
                    js_content = requests.get(js_link, timeout=5, verify=False).text
                    for name, pattern in patterns.items():
                        matches = re.findall(pattern, js_content)
                        if matches:
                            findings.append(f"🚨 Found {name} in {js_link.split('/')[-1]}: {matches[0]}")
                except: pass

            return "\n".join(findings) if len(findings) > 1 else "✅ No obvious secrets found in JS files."

        except Exception as e:
            return f"❌ JS Scan Error: {str(e)}"

# =====================================================
# 3️⃣ SHODAN PASSIVE SCANNER
# =====================================================

class ShodanInput(BaseModel):
    target: Optional[str] = Field(None, description="Target IP or Domain.")
    host: Optional[str] = Field(None, description="Target Host.")

class ShodanTool(BaseTool):
    name: str = "Shodan Passive Scan"
    description: str = "Uses Shodan API to find open ports. Input must be JSON: {'target': 'domain.com'}."
    args_schema: Type[BaseModel] = ShodanInput

    def _run(self, **kwargs) -> str:
        target_ip = extract_target_ip(kwargs)
        
        if not target_ip:
            return f"❌ Error: Could not extract target from input. You sent: {list(kwargs.keys())}"

        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return "❌ Error: SHODAN_API_KEY not found in .env file."

        try:
            api = shodan.Shodan(api_key)
            host = None

            # 1. Try direct Host lookup
            try:
                host = api.host(target_ip)
            except shodan.APIError:
                pass

            # 2. If Host lookup fails, try Search
            if not host:
                try:
                    results = api.search(target_ip)
                    if results['total'] > 0:
                        host = results['matches'][0]
                except:
                    pass

            if not host:
                return f"⚠️ No Shodan data found for {target_ip}. Target might be new or not indexed."

            # 3. Format Output
            output = [f"✅ Shodan Report for: {host.get('ip_str')} ({host.get('org', 'n/a')})"]
            output.append(f"OS: {host.get('os', 'Unknown')}")
            output.append("------------------------------------------------")
            
            data_source = host.get('data', []) if 'data' in host else [host]
            
            for item in data_source:
                port = item.get('port', 'Unknown')
                product = item.get('product', 'Unknown Service')
                version = item.get('version', '')
                output.append(f"🔌 Port {port}: {product} {version}")
            
            if 'vulns' in host:
                output.append("\n⚠️ Known Vulns (Passive):")
                vulns_list = list(host['vulns'])
                output.append(", ".join(vulns_list[:5]))

            return "\n".join(output)

        except Exception as e:
            return f"❌ Shodan Error: {str(e)}"

# =====================================================
# 4️⃣ PYTHON WEB VULN SCANNER (Flexible Inputs)
# =====================================================

class WebScanInput(BaseModel):
    target: Optional[str] = Field(None, description="Target Domain or URL.")
    url: Optional[str] = Field(None, description="Target URL.")
    query: Optional[str] = Field(None, description="Target Query.")
    host: Optional[str] = Field(None, description="Target Host.") # 🔥 Added host support

class NiktoTool(BaseTool):
    name: str = "Nikto Web Scanner" 
    description: str = "Scans web servers for dangerous headers, sensitive files, and version leaks (Python Native)."
    args_schema: Type[BaseModel] = WebScanInput

    def _run(self, **kwargs) -> str:
        target_url = extract_url(kwargs)
        
        if not target_url:
            return f"❌ Error: No valid URL provided. Inputs: {list(kwargs.keys())}"

        findings = []
        findings.append(f"🔍 Scanning {target_url} ...\n")

        try:
            # 1. Check Headers
            r = requests.get(target_url, timeout=10, verify=False)
            headers = r.headers
            
            security_headers = [
                "X-Frame-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options"
            ]
            
            missing_headers = [h for h in security_headers if h not in headers]
            if missing_headers:
                findings.append(f"🚨 Missing Security Headers: {', '.join(missing_headers)}")
            else:
                findings.append("✅ All key security headers are present.")

            # Version Disclosure
            if "Server" in headers:
                findings.append(f"⚠️ Server Version Disclosed: {headers['Server']}")
            if "X-Powered-By" in headers:
                findings.append(f"⚠️ Technology Disclosed: {headers['X-Powered-By']}")

            # 2. Check for Dangerous Files
            dangerous_files = [
                "robots.txt", ".env", "config.php.bak", 
                "wp-config.php.bak", ".git/HEAD", "admin/"
            ]
            
            findings.append("\n📂 File Discovery:")
            found_files = []
            
            for file in dangerous_files:
                try:
                    check_url = f"{target_url.rstrip('/')}/{file}"
                    file_r = requests.head(check_url, timeout=3, verify=False)
                    if file_r.status_code == 200:
                        found_files.append(f"  - Found: {file} (200 OK)")
                    elif file_r.status_code == 403:
                        found_files.append(f"  - Found: {file} (403 Forbidden - Interesting!)")
                except:
                    pass
            
            if found_files:
                findings.extend(found_files)
            else:
                findings.append("  - No obvious sensitive files found in quick scan.")

            return "\n".join(findings)

        except Exception as e:
            return f"❌ Scan Failed: {str(e)}"

# =====================================================
# 5️⃣ NIST CVE SEARCH (API)
# =====================================================

class CVEInput(BaseModel):
    service: str = Field(..., description="Service name (e.g. 'apache', 'nginx').")
    version: str = Field(..., description="Version number (e.g. '2.4.49').")

class CVESearchTool(BaseTool):
    name: str = "NIST CVE Search"
    description: str = "Query NIST API for CVEs. Requires 'service' and 'version'."
    args_schema: Type[BaseModel] = CVEInput

    def _run(self, **kwargs) -> str:
        service = kwargs.get("service")
        version = kwargs.get("version")

        if not service or not version:
            return "❌ Error: Service name and version are required."

        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        query = f"{service} {version}"
        params = {"keywordSearch": query, "resultsPerPage": 2}
        headers = {"User-Agent": "RedSec-Bot"}

        try:
            response = requests.get(base_url, params=params, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    return f"✅ No direct CVEs found for {service} {version}."

                report = []
                for item in vulnerabilities:
                    cve_id = item["cve"]["id"]
                    desc = item["cve"]["descriptions"][0]["value"][:120]
                    report.append(f"🔻 {cve_id}: {desc}...")
                
                return "\n".join(report)
            return f"❌ API Error: {response.status_code}"
        except:
            return "❌ CVE Connection Error."

# =====================================================
# 6️⃣ QUICK DIRECTORY CHECK
# =====================================================

class DirectorySearchTool(BaseTool):
    name: str = "Quick Dir Check"
    description: str = "Checks common paths (/admin, /login)."
    args_schema: Type[BaseModel] = WebScanInput # Uses the flexible schema

    def _run(self, **kwargs) -> str:
        url = extract_url(kwargs)
        if not url: return "No target"
        
        paths = ["admin", "login", "dashboard", "panel"]
        found = []
        
        for p in paths:
            try:
                r = requests.head(f"{url.rstrip('/')}/{p}", timeout=3, verify=False)
                if r.status_code in [200, 301, 302]:
                    found.append(f"/{p} ({r.status_code})")
            except:
                pass
        return f"📂 Found Paths: {found if found else 'None'}"