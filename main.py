# main.py - Dynamic Rotating Proxy Server on Render (Free, No Manual Work)
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

# === LOGGING ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === FASTAPI APP ===
app = FastAPI(title="Free Dynamic Rotating Proxy on Render")

# === AUTHENTICATION ===
security = HTTPBasic()
USERNAME = os.getenv("PROXY_USER", "user")        # Set in Render Dashboard
PASSWORD = os.getenv("PROXY_PASS", "pass")        # Set in Render Dashboard

def verify_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != USERNAME or credentials.password != PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# === CORS (Allow all) ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === PROXY POOL ===
PROXY_POOL: list[str] = []
POOL_LOCK = asyncio.Lock()
LAST_FETCH = datetime.min
FETCH_INTERVAL = timedelta(minutes=30)  # Refresh every 30 mins

# === FETCH PROXIES FROM freeproxy.world (No blocking, 1000+ free proxies) ===
async def fetch_proxies():
    global PROXY_POOL, LAST_FETCH
    if datetime.now() - LAST_FETCH < FETCH_INTERVAL and PROXY_POOL:
        return

    url = "https://freeproxy.world/api/proxy"
    params = {
        "page": 1,
        "limit": 50,
        "anonymity": "elite,anonymous",
        "type": "http",
        "country": "",
        "timeout": 5000
    }

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
        try:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    logger.warning(f"Proxy API failed: HTTP {resp.status}")
                    return
                data = await resp.json()
                candidates = []
                for item in data.get("data", []):
                    ip = item.get("ip")
                    port = item.get("port")
                    if ip and port:
                        candidates.append(f"{ip}:{port}")
                logger.info(f"Fetched {len(candidates)} proxy candidates from freeproxy.world")

                if not candidates:
                    return

                # Validate up to 30 proxies in parallel
                sample = random.sample(candidates, min(30, len(candidates)))
                tasks = [test_proxy(session, f"http://{ip_port}") for ip_port in sample]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                valid = [sample[i] for i, r in enumerate(results) if r is True]

                async with POOL_LOCK:
                    PROXY_POOL = valid[:15]  # Keep top 15 working
                    LAST_FETCH = datetime.now()
                logger.info(f"Validated {len(PROXY_POOL)} working proxies: {PROXY_POOL[:3] if PROXY_POOL else 'none'}")

        except Exception as e:
            logger.error(f"Proxy fetch error: {e}")

# === TEST PROXY ===
async def test_proxy(session: aiohttp.ClientSession, proxy_url: str) -> bool:
    try:
        async with session.get(
            "http://httpbin.org/ip",
            proxy=proxy_url,
            timeout=6
        ) as resp:
            return resp.status == 200
    except:
        return False

# === STARTUP: Fetch proxies in background ===
@app.on_event("startup")
async def startup():
    asyncio.create_task(fetch_proxies())  # Non-blocking

# === MAIN PROXY ENDPOINT ===
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, full_path: str, user: str = Depends(verify_auth)):
    target = request.query_params.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="Missing '?target=' parameter. Example: ?target=https://httpbin.org/ip")

    # Ensure we have proxies
    await fetch_proxies()
    async with POOL_LOCK:
        if not PROXY_POOL:
            raise HTTPException(status_code=503, detail="No working proxies available. Retrying...")

    # Rotate: Pick random working proxy
    proxy_ip_port = random.choice(PROXY_POOL)
    proxy_url = f"http://{proxy_ip_port}"

    try:
        # Parse target URL
        parsed = urllib.parse.urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(status_code=400, detail="Invalid target URL")

        # Build full path
        path = parsed.path or "/"
        if full_path:
            path = f"{path.rstrip('/')}/{full_path.lstrip('/')}"
        final_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, path,
            parsed.params, parsed.query, parsed.fragment
        ))

        # Forward query params (except 'target')
        params = {k: v for k, v in request.query_params.items() if k != "target"}
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ["host", "content-length", "connection", "transfer-encoding"]
        }
        body = await request.body()

        # Use rotated proxy for outbound request
        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            proxies={"http://": proxy_url, "https://": proxy_url}
        ) as client:
            req = client.build_request(
                method=request.method,
                url=final_url,
                headers=headers,
                content=body or None,
                params=params
            )
            response = await client.send(req, stream=True)

            async def stream_response():
                try:
                    async for chunk in response.aiter_bytes():
                        if chunk:
                            yield chunk
                except Exception as e:
                    logger.warning(f"Stream failed via {proxy_ip_port}: {e}")
                finally:
                    await response.aclose()

            return StreamingResponse(
                stream_response(),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )

    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Proxy failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# === HEALTH CHECK ===
@app.get("/health")
async def health():
    await fetch_proxies()
    async with POOL_LOCK:
        return {
            "status": "ok",
            "active_proxies": len(PROXY_POOL),
            "sample": PROXY_POOL[:3] if PROXY_POOL else [],
            "last_updated": LAST_FETCH.isoformat() if LAST_FETCH != datetime.min else "never",
            "instructions": "Use: curl -x http://user:pass@your-proxy.onrender.com:443/?target=https://example.com"
        }
