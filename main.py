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

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Dynamic Rotating Proxy on Render")

# Basic Auth (set USER/PASS in Render Env Vars)
security = HTTPBasic()
USERNAME = os.getenv("PROXY_USER", "user")
PASSWORD = os.getenv("PROXY_PASS", "pass")

def verify_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != USERNAME or credentials.password != PASSWORD:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return credentials.username

# CORS
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Proxy pool: {ip:port: 'user:pass'} — but since free, user/pass optional per proxy
PROXY_POOL = []
POOL_LOCK = asyncio.Lock()
LAST_FETCH = datetime.now() - timedelta(hours=1)  # Force initial fetch
FETCH_INTERVAL = timedelta(minutes=30)

async def fetch_proxies():
    """Dynamically fetch & validate free proxies from Proxyscrape (no signup)."""
    global PROXY_POOL, LAST_FETCH
    if datetime.now() - LAST_FETCH < FETCH_INTERVAL and PROXY_POOL:
        return
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        # Fetch plain text list (HTTP proxies)
        url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    lines = await resp.text()
                    candidates = [line.strip() for line in lines.split('\n') if ':' in line and len(line.split(':')) == 2]
                    logger.info(f"Fetched {len(candidates)} candidate proxies")
                    
                    # Validate in parallel (test httpbin.org/ip)
                    tasks = []
                    for ip_port in random.sample(candidates, min(50, len(candidates))):  # Sample for speed
                        ip, port = ip_port.split(':')
                        proxy_url = f"http://{ip}:{port}"
                        task = test_proxy(session, proxy_url)
                        tasks.append((ip_port, task))
                    
                    valid = []
                    for ip_port, task in asyncio.as_completed(tasks):
                        if await task:
                            valid.append(ip_port)  # Format: ip:port (add dummy user:pass if needed)
                    
                    async with POOL_LOCK:
                        PROXY_POOL = valid[:20]  # Keep top 20 working
                        LAST_FETCH = datetime.now()
                    logger.info(f"Validated {len(PROXY_POOL)} working proxies")
        except Exception as e:
            logger.error(f"Proxy fetch failed: {e}")

async def test_proxy(session, proxy_url):
    """Test if proxy works."""
    try:
        async with session.get("http://httpbin.org/ip", proxy=proxy_url, timeout=5) as resp:
            return resp.status == 200
    except:
        return False

@app.on_event("startup")
async def startup():
    await fetch_proxies()  # Initial load

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(
    request: Request,
    full_path: str,
    credentials: str = Depends(verify_auth)  # Enforces auth
):
    target_url = request.query_params.get("target")
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing 'target' query param")

    await fetch_proxies()  # Refresh if needed
    if not PROXY_POOL:
        raise HTTPException(status_code=503, detail="No proxies available—retrying...")

    # Rotate: Pick random proxy
    ip_port = random.choice(PROXY_POOL)
    ip, port = ip_port.split(':')
    proxy_auth = "dummy:dummy"  # Free proxies usually no auth; customize if needed
    outbound_proxy = f"http://{proxy_auth}@{ip}:{port}" if proxy_auth else f"http://{ip}:{port}"

    try:
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(status_code=400, detail="Invalid target URL")

        path = parsed.path or "/"
        if full_path:
            path = f"{path.rstrip('/')}/{full_path.lstrip('/')}"
        final_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))

        params = {k: v for k, v in request.query_params.items() if k != "target"}
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length", "transfer-encoding", "connection"]}
        body = await request.body()

        async with httpx.AsyncClient(
            timeout=30.0, follow_redirects=True,
            proxies={ "http://": outbound_proxy, "https://": outbound_proxy }  # Use rotated proxy
        ) as client:
            req = client.build_request(method=request.method, url=final_url, headers=headers, content=body or None, params=params)
            response = await client.send(req, stream=True)

            async def stream_response():
                try:
                    async for chunk in response.aiter_bytes():
                        if chunk:
                            yield chunk
                except Exception as e:
                    logger.warning(f"Stream error via {ip}:{port}: {e}")
                finally:
                    await response.aclose()

            return StreamingResponse(
                stream_response(),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )

    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Proxy rotation failed: {str(e)}")
    except Exception as e:
        logger.error(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Server error")

# Health check
@app.get("/health")
async def health():
    await fetch_proxies()
    return {"status": "ok", "proxies": len(PROXY_POOL)}
