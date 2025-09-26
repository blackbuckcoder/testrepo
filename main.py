"""
Gowher SecTest - Web Application Security Scanner (MVP)
Single-file FastAPI app (Python) implementing:




URL input -> subdomain discovery (passive + brute wordlist)


Directory fuzzing (simple wordlist)


Clickjacking checks (header-based) across discovered hosts


Optional AI integration using your GenAI API details




How to run:




Create a venv: python -m venv venv && source venv/bin/activate


Install: pip install fastapi uvicorn aiohttp dnspython httpx jinja2 python-multipart


Run: uvicorn web_scanner_mvp:app --reload --port 8000


Open http://localhost:8000 in browser




Notes:




This is an MVP and intentionally conservative: active intrusive tests (aggressive brute force, exploit attempts) are NOT included by default.


Before running intrusive scans, ensure you have permission to scan the target.




Placeholders / config you should edit before using in production:




AI_API_URL, GENAI_CLIENT, OPENAI_TOKEN: set to your AI provider endpoint and keys.




"""


from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncio
import aiohttp
import dns.resolver
import socket
import httpx
import time
import re
import json
from typing import List, Dict, Any


app = FastAPI(title="Gowher SecTest - Web Scanner MVP")


templates = Jinja2Templates(directory="templates")


--- Configuration ---


AI_API_URL = "https://your.genai.endpoint/v1/generate"  # replace with your GenAI API url
GENAI_CLIENT = "Genai_client"  # header key or client id name as you mentioned
OPENAI_TOKEN = "Openai_token"  # header name for token (put real value in environment / config)


small embedded wordlists for MVP; replace with larger files for production


SUBDOMAIN_WORDS = [
"www", "dev", "staging", "api", "test", "mail", "m", "beta", "admin", "portal"
]
DIR_WORDS = [
"admin/", "login/", "dashboard/", "backup.zip", ".env", "config.php", "uploads/", "old/"
]


simple user-agent for requests


DEFAULT_HEADERS = {"User-Agent": "GowherSecTestScanner/1.0"}


Basic severity mapping helper


SEVERITY = {
"info": 0,
"low": 1,
"medium": 2,
"high": 3,
"critical": 4,
}


--- Utility functions ---


async def fetch_head(url: str, timeout: int = 10) -> Dict[str, Any]:
"""Perform HTTP HEAD (fall back to GET) and return status and headers."""
timeout_cfg = aiohttp.ClientTimeout(total=timeout)
async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
try:
async with session.head(url, allow_redirects=True, headers=DEFAULT_HEADERS) as resp:
text = await resp.text() if resp.content_length and resp.content_length < 10000 else ""
return {"status": resp.status, "headers": dict(resp.headers), "url": str(resp.url), "body_sample": text}
except aiohttp.ClientResponseError:
# fallback to GET
try:
async with session.get(url, allow_redirects=True, headers=DEFAULT_HEADERS) as resp:
text = await resp.text() if resp.content_length and resp.content_length < 10000 else ""
return {"status": resp.status, "headers": dict(resp.headers), "url": str(resp.url), "body_sample": text}
except Exception as e:
return {"error": str(e)}
except Exception as e:
return {"error": str(e)}


def normalize_url(url: str) -> str:
url = url.strip()
if not re.match(r"^https?://", url):
url = "https://" + url
return url.rstrip("/")


async def resolve_host(host: str, timeout: float = 3.0) -> List[str]:
"""Resolve DNS A records; returns list of IPs or empty on failure."""
loop = asyncio.get_event_loop()
try:
# use dnspython resolver
answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(host, "A", lifetime=timeout))
return [str(rdata) for rdata in answers]
except Exception:
# attempt socket.gethostbyname
try:
ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(host))
return [ip]
except Exception:
return []


async def passive_subdomain_enumeration(root_host: str, words: List[str]) -> List[str]:
"""Try common subdomains using DNS resolution; non-intrusive."""
found = []
tasks = []
for w in words:
candidate = f"{w}.{root_host}"
tasks.append(asyncio.create_task(resolve_host(candidate)))
results = await asyncio.gather(*tasks)
for i, res in enumerate(results):
if res:
found.append(f"{words[i]}.{root_host}")
# always include root_host
if root_host not in found:
found.insert(0, root_host)
return found


async def check_clickjacking_headers(url: str) -> Dict[str, Any]:
"""Check for presence of X-Frame-Options and CSP frame-ancestors. Returns verdict and evidence."""
r = await fetch_head(url)
if "error" in r:
return {"ok": False, "error": r.get("error")}
headers = {k.lower(): v for k, v in r.get("headers", {}).items()}
xfo = headers.get("x-frame-options")
csp = headers.get("content-security-policy")
vulnerable = False
reasons = []
if not xfo:
reasons.append("Missing X-Frame-Options")
else:
# if XFO present but not DENY or SAMEORIGIN, flag
if not re.search(r"DENY|SAMEORIGIN", xfo, re.I):
reasons.append(f"X-Frame-Options present but not strict: {xfo}")
if not csp:
reasons.append("Missing Content-Security-Policy (frame-ancestors not set)")
else:
if not re.search(r"frame-ancestors", csp):
reasons.append("CSP present but frame-ancestors directive missing")
else:
# check for unsafe wildcard
m = re.search(r"frame-ancestors\s+([^;]+)", csp)
if m:
fa = m.group(1)
if "*" in fa:
reasons.append(f"CSP frame-ancestors allows wildcard: {fa}")
if reasons:
vulnerable = True
return {"ok": True, "vulnerable": vulnerable, "reasons": reasons, "status": r.get("status"), "url": r.get("url")}


async def directory_fuzz(target_base: str, words: List[str], concurrency: int = 10, timeout: int = 8) -> List[Dict[str, Any]]:
"""Simple directory fuzzing using HEAD requests; returns list of found paths and status."""
sem = asyncio.Semaphore(concurrency)
results = []


async def worker(path: str):
    async with sem:
        url = f"{target_base.rstrip('/')}/{path.lstrip('/')}"
        r = await fetch_head(url, timeout=timeout)
        entry = {"path": path, "url": url}
        if "error" in r:
            entry.update({"error": r.get("error")})
        else:
            entry.update({"status": r.get("status"), "headers": r.get("headers")})
        results.append(entry)

tasks = [asyncio.create_task(worker(p)) for p in words]
await asyncio.gather(*tasks)
# coarse filter: return items with status 200/301/302/403 etc (non-404)
filtered = [r for r in results if r.get("status") and r.get("status") != 404]
return filtered



async def call_ai_summary(api_url: str, genai_client: str, openai_token: str, prompt: str) -> Dict[str, Any]:
"""Call your GenAI endpoint (simple wrapper). Adjust according to your provider's API spec."""
# NOTE: This is a simple example using HTTP POST with JSON body. Your provider may differ.
headers = {
"Content-Type": "application/json",
"Authorization": f"Bearer {openai_token}",
"x-genai-client": genai_client,
}
payload = {"prompt": prompt, "max_tokens": 400}
async with httpx.AsyncClient(timeout=20.0) as client:
try:
resp = await client.post(api_url, json=payload, headers=headers)
if resp.status_code >= 400:
return {"error": f"AI API returned {resp.status_code}: {resp.text}"}
data = resp.json()
return {"ok": True, "data": data}
except Exception as e:
return {"error": str(e)}


--- API endpoints ---


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
# simple HTML UI served from templates/index.html (created by developer)
html = """



<meta charset="utf-8">





Gowher SecTest - Web Scanner (MVP)


Enter a URL and choose scans. This MVP does passive subdomain enumeration (common list), header-based clickjacking checks, and simple directory fuzzing.

Target URL



 Find Subdomains (passive)
 Directory fuzzing
 Clickjacking (headers check)
 Use AI for summary/remediation


Start Scan




Result


No results yet




"""
return HTMLResponse(html)



@app.post("/api/scan")
async def api_scan(payload: Dict[str, Any]):
"""Main orchestrator: accepts JSON payload with keys:
{ "url": "example.com", "url_flags": {subdomains: bool, directory: bool, clickjacking: bool}, "use_ai": bool }
Returns structured findings.
"""
url = payload.get("url")
if not url:
raise HTTPException(status_code=400, detail="Missing url")
flags = payload.get("url_flags", {})
do_subs = bool(flags.get("subdomains", False))
do_dirs = bool(flags.get("directory", False))
do_click = bool(flags.get("clickjacking", False))
use_ai = bool(payload.get("use_ai", False))


normalized = normalize_url(url)
# extract host
m = re.match(r"https?://([^/]+)", normalized)
if not m:
    raise HTTPException(status_code=400, detail="Unable to parse host")
host = m.group(1)
root_host = host

result = {"target": normalized, "scanned_at": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), "findings": []}

# 1) Subdomain enumeration (passive list)
subdomains = [root_host]
if do_subs:
    subdomains = await passive_subdomain_enumeration(root_host, SUBDOMAIN_WORDS)
result["subdomains"] = subdomains

# 2) For each subdomain, perform checks requested
all_checks = []
for sub in subdomains:
    base = f"https://{sub}"
    node = {"host": sub, "url": base, "checks": []}
    if do_click:
        cj = await check_clickjacking_headers(base)
        node["checks"].append({"type": "clickjacking", "result": cj})
        if cj.get("vulnerable"):
            result["findings"].append({
                "id": f"CJ-{sub}",
                "type": "clickjacking",
                "severity": "high",
                "host": sub,
                "details": cj.get("reasons"),
                "url": cj.get("url")
            })
    if do_dirs:
        # run directory fuzzing on the root path of this host
        fuzz = await directory_fuzz(base, DIR_WORDS)
        node["checks"].append({"type": "dir_fuzz", "result": fuzz})
        for f in fuzz:
            # if sensitive files detected (env, config, backup), mark critical
            p = f.get("path","")
            sev = "low"
            if re.search(r"\.env|backup|config|phpinfo|\.git|\.svn", p, re.I):
                sev = "critical"
            result["findings"].append({
                "id": f"DIR-{sub}-{p}",
                "type": "directory",
                "severity": sev,
                "host": sub,
                "details": {"path": p, "status": f.get("status"), "url": f.get("url")}
            })
    all_checks.append(node)

result["checked"] = all_checks

# 3) Optionally call AI to produce a summarized remediation
if use_ai:
    # Build prompt from findings
    prompt = build_ai_prompt(result)
    ai_resp = await call_ai_summary(AI_API_URL, GENAI_CLIENT, OPENAI_TOKEN, prompt)
    result["ai"] = ai_resp

return JSONResponse(result)



def build_ai_prompt(scan_result: Dict[str, Any]) -> str:
"""Construct a detailed prompt to send to the GenAI model for remediation and summary."""
header = (
"You are an expert web security engineer. You will be given scan results from a web application scanner. "
"For each finding, provide: 1) Plain-language explanation of the issue, 2) Risk/impact, 3) Concrete remediation steps (commands, configuration lines, code snippets where applicable), 4) Example of a safe configuration, and 5) Relevant security references or OWASP mappings. "
"Be concise and format output in JSON with keys: findings (list), summary (short), recommendations (list).\n\n"
)
body = json.dumps(scan_result, indent=2)
prompt = header + "SCAN_RESULT:\n" + body + "\n\nRespond in valid JSON."
return prompt


@app.get('/poc/iframe', response_class=HTMLResponse)
async def iframe_poc(target: str = ''):
"""Serve a simple PoC page that attempts to iframe the target URL — useful for manual clickjacking proof.
Use: /poc/iframe?target=https://example.com
"""
if not target:
return PlainTextResponse('Provide ?target=https://example.com')
safe = target if target.startswith('http') else f'https://{target}'
html = f"""





Attempting to iframe {safe}

<iframe src="{safe}" style="width:1000px;height:700px;border:3px solid #444">

If the iframe renders, the target may be frameable (possible clickjacking risk). Some sites still prevent rendering via CSP or X-Frame-Options.



"""
return HTMLResponse(html)



--- Simple health endpoint ---


@app.get('/health')
async def health():
return {"status": "ok"}


--- If run as script ---


if name == 'main':
import uvicorn
uvicorn.run('web_scanner_mvp:app', host='0.0.0.0', port=8000, reload=True)


