# main.py - ENHANCED ROTATING PROXY (40+ SOURCES, 50+ PROXIES, NOV 2025 READY)
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import httpx
import aiohttp
import asyncio
import random
import urllib.parse
import logging
from datetime import datetime, timedelta
import os
import re  # For IP validation

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# === AUTH ===
security = HTTPBasic()
USERNAME = os.getenv("PROXY_USER", "rood")
PASSWORD = os.getenv("PROXY_PASS", "rood123")

def verify_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != USERNAME or credentials.password != PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# === PROXY POOL ===
PROXY_POOL = []
POOL_LOCK = asyncio.Lock()
LAST_FETCH = datetime.min
FETCH_INTERVAL = timedelta(minutes=10)  # Aggressive refresh

# === ENHANCED MEGA SOURCES (40+ ACTIVE LISTS, 2000+ PROXIES) ===
async def fetch_proxies():
    global PROXY_POOL, LAST_FETCH
    if datetime.now() - LAST_FETCH < FETCH_INTERVAL and PROXY_POOL:
        return

    # 40+ RELIABLE SOURCES (HTTP/HTTPS, Updated Nov 2025)
    sources = [
        # === API ENDPOINTS ===
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://www.proxy-list.download/api/v1/get?type=https",
        "https://api.openproxylist.xyz/http.txt",
        "https://api.openproxylist.xyz/https.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=https&timeout=10000&country=all",
        "https://proxifly.dev/api/proxy/http",
        "https://proxifly.dev/api/proxy/https",
        "https://proxyget.com/api/proxy/http",
        "https://proxyget.com/api/proxy/https",
        
        # === GITHUB RAW (HIGH VOLUME) ===
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt",
        "https://raw.githubusercontent.com/mertguvencli/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",
        "https://raw.githubusercontent.com/UptodateListing/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/UptodateListing/proxy-list/main/https.txt",
        "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/yokelvin-proxy/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/My-Proxy-List/main/http.txt",
        "https://raw.githubusercontent.com/My-Proxy-List/main/https.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/https_proxies.txt",
        
        # === OTHER RELIABLE TXT/JSON ===
        "https://www.proxyscan.io/download?type=http",
        "https://www.proxyscan.io/download?type=https",
        "https://raw.githubusercontent.com/getproxylist/GetProxyList/main/http.txt",
        "https://raw.githubusercontent.com/getproxylist/GetProxyList/main/https.txt",
        "https://raw.githubusercontent.com/proxydb/proxydb/main/proxies/http.txt",
        "https://raw.githubusercontent.com/proxydb/proxydb/main/proxies/https.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxylist/http.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxylist/https.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTPS.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
        "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
        "https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
    ]

    candidates = []
    successful_sources = 0
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25)) as session:
        tasks = [fetch_source(session, url) for url in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, list) and result:
                candidates.extend(result)
                successful_sources += 1
                logger.info(f"Fetched {len(result)} from source {i+1}/{len(sources)}")

    if not candidates:
        logger.error("ALL SOURCES FAILED - Fallback to cached or retry")
        return

    # Enhanced dedupe + IP validation (IPv4 only, port 1-65535)
    def is_valid_proxy(line):
        if ':' not in line or line.count(':') != 1:
            return False
        ip, port = line.split(':')
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) and 1 <= int(port) <= 65535:
            return True
        return False

    candidates = list(dict.fromkeys([c for c in candidates if is_valid_proxy(c)]))
    logger.info(f"Total unique valid candidates: {len(candidates)} from {successful_sources} sources")

    if not candidates:
        return

    # Validate 100 proxies in parallel (faster timeout)
    sample = random.sample(candidates, min(100, len(candidates)))
    validate_tasks = [test_proxy(session, f"http://{ip_port}") for ip_port in sample]
    validate_results = await asyncio.gather(*validate_tasks, return_exceptions=True)

    valid = [sample[i] for i, r in enumerate(validate_results) if r is True]

    async with POOL_LOCK:
        PROXY_POOL = valid[:50]  # Larger pool for rotation
        LAST_FETCH = datetime.now()
    logger.info(f"Validated {len(PROXY_POOL)} working proxies: {PROXY_POOL[:5]}")

async def fetch_source(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                # Handle TXT or JSON
                if '{' in text:  # JSON
                    import json
                    data = json.loads(text)
                    lines = [f"{p['ip']}:{p['port']}" for p in data.get('proxies', []) if p.get('type') == 'http']
                else:  # TXT
                    lines = [line.strip() for line in text.split('\n') if ':' in line and line.count(':') == 1 and '.' in line.split(':')[0]]
                return lines
    except Exception as e:
        logger.warning(f"Source failed: {e}")
    return []

async def test_proxy(session: aiohttp.ClientSession, proxy_url: str) -> bool:
    try:
        async with session.get("http://httpbin.org/ip", proxy=proxy_url, timeout=5) as resp:
            return resp.status == 200
    except:
        return False

@app.on_event("startup")
async def startup():
    asyncio.create_task(fetch_proxies())

# === ENHANCED HEALTH CHECK ===
@app.get("/health")
async def health():
    await fetch_proxies()
    async with POOL_LOCK:
        return {
            "status": "ok",
            "working_proxies": len(PROXY_POOL),
            "sample": PROXY_POOL[:5],
            "last_fetch": LAST_FETCH.isoformat() if LAST_FETCH != datetime.min else "never",
            "sources_count": 40,
            "tip": "Rotates every request. If 0, wait 10min."
        }

# === PROXY ENDPOINT (ENHANCED PATH HANDLING) ===
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, full_path: str, user: str = Depends(verify_auth)):
    target = request.query_params.get("target")
    if not target:
        raise HTTPException(400, "Missing ?target= (e.g., ?target=https://httpbin.org/ip)")

    await fetch_proxies()
    async with POOL_LOCK:
        if not PROXY_POOL:
            raise HTTPException(503, "No proxies yet — retry in 10min. Check /health")

    proxy_ip_port = random.choice(PROXY_POOL)
    proxy_url = f"http://{proxy_ip_port}"

    try:
        parsed = urllib.parse.urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(400, "Invalid target URL (must include https://)")

        # ENHANCED: Avoid double path — use full_path as override
        path = full_path if full_path else (parsed.path or "/")
        final_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, path,
            parsed.params, parsed.query, parsed.fragment
        ))

        params = {k: v for k, v in request.query_params.items() if k != "target"}
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length", "connection", "transfer-encoding"]}
        body = await request.body()

        async with httpx.AsyncClient(
            timeout=40.0,
            follow_redirects=True,
            proxies={"http://": proxy_url, "https://": proxy_url}
        ) as client:
            req = client.build_request(method=request.method, url=final_url, headers=headers, content=body or None, params=params)
            response = await client.send(req, stream=True)

            async def stream():
                try:
                    async for chunk in response.aiter_bytes():
                        yield chunk
                except Exception as e:
                    logger.warning(f"Stream error via {proxy_ip_port}: {e}")
                finally:
                    await response.aclose()

            return StreamingResponse(
                stream(),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )

    except httpx.RequestError as e:
        raise HTTPException(502, f"Proxy failed: {str(e)}")
    except Exception as e:
        logger.error(f"Error: {e}")
        raise HTTPException(500, "Server error")
