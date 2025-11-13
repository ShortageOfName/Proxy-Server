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

app = FastAPI(title="Dynamic Rotating Proxy on Render")

# === AUTH ===
security = HTTPBasic()
USERNAME = os.getenv("PROXY_USER", "user")
PASSWORD = os.getenv("PROXY_PASS", "pass")

def verify_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != USERNAME or credentials.password != PASSWORD:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return credentials.username

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# === PROXY POOL ===
PROXY_POOL = []
POOL_LOCK = asyncio.Lock()
LAST_FETCH = datetime.min
FETCH_INTERVAL = timedelta(minutes=30)

async def fetch_proxies():
    global PROXY_POOL, LAST_FETCH
    if datetime.now() - LAST_FETCH < FETCH_INTERVAL and PROXY_POOL:
        return

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
        url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=elite,anonymous"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    logger.warning(f"Proxy list fetch failed: {resp.status}")
                    return
                text = await resp.text()
                candidates = [line.strip() for line in text.split('\n') if ':' in line]
                logger.info(f"Fetched {len(candidates)} proxy candidates")

                # Validate up to 50 in parallel
                sample = random.sample(candidates, min(50, len(candidates)))
                tasks = [test_proxy(session, f"http://{ip_port}") for ip_port in sample]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                valid = [sample[i] for i, r in enumerate(results) if r is True]
                
                async with POOL_LOCK:
                    PROXY_POOL = valid[:20]  # Keep best 20
                    LAST_FETCH = datetime.now()
                logger.info(f"Validated {len(PROXY_POOL)} working proxies: {PROXY_POOL[:3]}...")

        except Exception as e:
            logger.error(f"Proxy fetch error: {e}")

async def test_proxy(session: aiohttp.ClientSession, proxy_url: str) -> bool:
    try:
        async with session.get("http://httpbin.org/ip", proxy=proxy_url, timeout=6) as resp:
            return resp.status == 200
    except:
        return False

# === Startup ===
@app.on_event("startup")
async def startup():
    asyncio.create_task(fetch_proxies())  # Non-blocking

# === Proxy Endpoint ===
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

        path = parsed.path or "/"
        if full_path:
            path = f"{path.rstrip('/')}/{full_path.lstrip('/')}"
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
            req = client.build_request(
                method=request.method,
                url=final_url,
                headers=headers,
                content=body or None,
                params=params
            )
            response = await client.send(req, stream=True)

            async def stream():
                try:
                    async for chunk in response.aiter_bytes():
                        yield chunk
                except Exception as e:
                    logger.warning(f"Stream failed via {proxy_ip_port}: {e}")
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

# === Health ===
@app.get("/health")
async def health():
    await fetch_proxies()
    return {"status": "ok", "proxies": len(PROXY_POOL), "sample": PROXY_POOL[:3] if PROXY_POOL else []}
