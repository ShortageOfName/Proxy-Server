from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
import httpx
import asyncio

app = FastAPI(title="Python Proxy on Render")

# Allow all CORS (optional, remove in production)
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, full_path: str):
    # Extract target URL from query param: ?target=https://httpbin.org/ip
    target_url = request.query_params.get("target")
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing 'target' query parameter")

    try:
        # Build full URL
        url = f"{target_url.rstrip('/')}/{full_path.lstrip('/')}"
        if request.query_params:
            # Preserve extra query params
            params = {k: v for k, v in request.query_params.items() if k != "target"}
        else:
            params = {}

        # Stream request body if present
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            # Forward headers (exclude host, content-length)
            headers = {
                k: v for k, v in request.headers.items()
                if k.lower() not in ["host", "content-length", "transfer-encoding"]
            }

            # Handle request body
            body = await request.body()
            if body:
                request_stream = httpx.Request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body,
                    params=params
                )
            else:
                request_stream = httpx.Request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    params=params
                )

            # Stream response back
            response = await client.send(request_stream.stream(), stream=True)

            return StreamingResponse(
                response.aiter_raw(),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )

    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Proxy error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")
