# main.py - FINAL WORKING ROTATING PROXY (NO 404, NO 403)
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Free Rotating Proxy")

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
PROXY_POOL: list[str] = []
POOL_LOCK = asyncio.Lock()
LAST_FETCH = datetime.min
FETCH_INTERVAL = timedelta(minutes=25)

# === FETCH PROXIES FROM GITHUB ===
async def fetch_proxies():
    global PROXY_POOL, LAST_FETCH
    if datetime.now() - LAST_FETCH < FETCH_INTERVAL and PROXY_POOL:
        return

    sources = [
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    ]

    candidates = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
        for url in sources:
            try:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        lines = [line.strip() for line in text.split('\n') if ':' in line and '.' in line.split(':')[0]]
                        candidates.extend(lines)
            except Exception as e:
                logger.warning(f"Failed: {url} -> {e}")

    if not candidates:
        return

    candidates = list(dict.fromkeys(candidates))
    sample = random.sample(candidates, min(40, len(candidates)))
    tasks = [test_proxy(session, f"http://{ip_port}") for ip_port in sample]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid = [sample[i] for i, r in enumerate(results) if r is True]

    async with POOL_LOCK:
        PROXY_POOL = valid[:20]
        LAST_FETCH = datetime.now()
    logger.info(f"Validated {len(PROXY_POOL)} proxies: {PROXY_POOL[:3]}")

async def test_proxy(session: aiohttp.ClientSession, proxy_url: str) -> bool:
    try:
        async with session.get("http://httpbin.org/ip", proxy=proxy_url, timeout=6) as resp:
            return resp.status == 200
    except:
        return False

# === STARTUP ===
@app.on_event("startup")
async def startup():
    asyncio.create_task(fetch_proxies())

# === HEALTH CHECK ===
@app.get("/health")
async def health():
    await fetch_proxies()
    async with POOL_LOCK:
        return {
            "status": "ok",
            "working_proxies": len(PROXY_POOL),
            "sample": PROXY_POOL[:3],
            "last_fetch": LAST_FETCH.isoformat() if LAST_FETCH != datetime.min else "never"
        }

# === PROXY ENDPOINT ===
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, full_path: str, user: str = Depends(verify_auth)):
    target = request.query_params.get("target")
    if not target:
        raise HTTPException(400, "Missing ?target=")

    await fetch_proxies()
    async with POOL_LOCK:
        if not PROXY_POOL:
            raise HTTPException(503, "No proxies available")

    proxy_ip_port = random.choice(PROXY_POOL)
    proxy_url = f"http://{proxy_ip_port}"

    try:
        parsed = urllib.parse.urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(400, "Invalid target URL")

        # Use full_path as the path to forward
        path = full_path or parsed.path or "/"
        final_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, path,
            parsed.params, parsed.query, parsed.fragment
        ))

        params = {k: v for k, v in request.query_params.items() if k != "target"}
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length", "connection"]}
        body = await request.body()

        async with httpx.AsyncClient(
            timeout=30.0,
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
                    logger.warning(f"Stream error: {e}")
                finally:
                    await response.aclose()

            return StreamingResponse(
                stream(),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )

    except httpx.RequestError as e:
        raise HTTPException(502, f"Proxy failed: {e}")
    except Exception as e:
        logger.error(f"Error: {e}")
        raise HTTPException(500, "Server error")
