import fnmatch
import ipaddress
import json
from pathlib import Path

import anyio
import httpx
import yt_dlp
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse

app = FastAPI()


_KEYS: dict[str, dict] | None = None


def _load_keys() -> None:
    global _KEYS
    path = Path("keys.json")
    if path.exists():
        _KEYS = json.loads(path.read_text())
    else:
        _KEYS = None


_load_keys()


def _client_ip(request: Request) -> str:
    xfwd = request.headers.get("x-forwarded-for")
    if xfwd:
        return xfwd.split(",", 1)[0].strip()
    return request.client.host  # type: ignore[attr-defined]


async def require_api_key(
    request: Request, authorization: str | None = Header(None)
) -> None:
    if _KEYS is None:
        return

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="missing or invalid authorization header"
        )

    key = authorization.split("Bearer ")[1]
    if key not in _KEYS:
        raise HTTPException(status_code=401, detail="invalid api key")

    rule = _KEYS[key]

    allowed_ips = rule.get("ips")
    if allowed_ips:
        client_ip = ipaddress.ip_address(_client_ip(request))
        if not any(
            client_ip in ipaddress.ip_network(cidr, strict=False)
            for cidr in allowed_ips
        ):
            raise HTTPException(status_code=403, detail="ip not allowed")

    allowed_agents = rule.get("userAgents")
    if allowed_agents:
        ua = request.headers.get("user-agent", "")
        if not any(fnmatch.fnmatch(ua, pattern) for pattern in allowed_agents):
            raise HTTPException(status_code=403, detail="user-agent not allowed")


def _select_format(info: dict) -> tuple[str, str]:
    formats = info.get("formats") or []
    if not formats:
        raise ValueError("no downloadable formats found")
    formats_sorted = sorted(formats, key=lambda f: f.get("height") or 0, reverse=True)
    for f in formats_sorted:
        url = f.get("url")
        if url:
            return url, f.get("ext", "mp4")
    raise ValueError("no downloadable formats with direct url found")


def _extract(video_url: str) -> tuple[str, str]:
    opts = {"quiet": True, "skip_download": True}
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(video_url, download=False)
    if "url" in info and not info.get("is_live"):  # type: ignore
        return info["url"], info.get("ext", "mp4")  # type: ignore
    return _select_format(info)  # type: ignore


async def extract(video_url: str) -> tuple[str, str]:
    return await anyio.to_thread.run_sync(_extract, video_url)  # type: ignore


@app.get("/info")
async def info():
    return {"status": "ok"}


@app.get("/video")
async def video(url: str, request: Request, _=Depends(require_api_key)):
    try:
        direct_url, ext = await extract(url)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    async def streamer():
        async with httpx.AsyncClient() as client:
            async with client.stream("GET", direct_url) as resp:
                resp.raise_for_status()
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(streamer(), media_type=f"video/{ext}")
