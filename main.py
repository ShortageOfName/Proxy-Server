from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import urllib.parse

app = FastAPI(title="Python Proxy on Render")

# Allow all CORS (remove in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, full_path: str):
    target_url = request.query_params.get("target")
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing 'target' query parameter. Usage: ?target=https://example.com")

    try:
        # Parse and rebuild target URL
        parsed_target = urllib.parse.urlparse(target_url)
        if not parsed_target.scheme or not parsed_target.netloc:
            raise HTTPException(status_code=400, detail="Invalid target URL")

        # Build full URL: target + path + extra query params
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
        path = parsed_target.path or "/"
        if full_path:
            path = f"{path.rstrip('/')}/{full_path.lstrip('/')}"
        final_url = urllib.parse.urlunparse((
            parsed_target.scheme,
            parsed_target.netloc,
            path,
            parsed_target.params,
            parsed_target.query,
            parsed_target.fragment
        ))

        # Preserve query params except 'target'
        params = {k: v for k, v in request.query_params.items() if k != "target"}

        # Forward headers (exclude host, content-length)
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ["host", "content-length", "transfer-encoding", "connection"]
        }

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            # Read body once
            body = await request.body()

            # Build request
            req = client.build_request(
                method=request.method,
                url=final_url,
                headers=headers,
                content=body or None,
                params=params
            )

            # Send and stream response
            response = await client.send(req, stream=True)

            return StreamingResponse(
                response.aiter_raw(),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )

    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Bad gateway: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proxy error: {str(e)}")
