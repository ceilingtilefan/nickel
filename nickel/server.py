import fnmatch
import ipaddress
import json
import urllib.request
from pathlib import Path
from typing import Iterable, Tuple

import anyio
import yt_dlp
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import iterate_in_threadpool

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
        raise HTTPException(status_code=401, detail="not authorized")

    rule = _KEYS[key]

    allowed_ips = rule.get("ips")
    if allowed_ips:
        client_ip = ipaddress.ip_address(_client_ip(request))
        if not any(
            client_ip in ipaddress.ip_network(cidr, strict=False)
            for cidr in allowed_ips
        ):
            raise HTTPException(status_code=403, detail="not authorized")

    allowed_agents = rule.get("userAgents")
    if allowed_agents:
        ua = request.headers.get("user-agent", "")
        if not any(fnmatch.fnmatch(ua, pattern) for pattern in allowed_agents):
            raise HTTPException(status_code=403, detail="not authorized")


def _select_format(info: dict) -> tuple[str, str, dict[str, str]]:
    formats = info.get("formats") or []
    if not formats:
        raise ValueError("no downloadable formats found")
    formats_sorted = sorted(formats, key=lambda f: f.get("height") or 0, reverse=True)
    for f in formats_sorted:
        url = f.get("url")
        if url:
            return (
                url,
                f.get("ext", "mp4"),
                f.get("http_headers") or info.get("http_headers") or {},
            )
    raise ValueError("no downloadable formats with direct url found")


def _extract(video_url: str) -> tuple[str, str, dict[str, str]]:
    opts = {"quiet": True, "skip_download": True}
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(video_url, download=False)
    if "url" in info and not info.get("is_live"):  # type: ignore
        headers = info.get("http_headers") or {}  # type: ignore
        print(headers)
        return info["url"], info.get("ext", "mp4"), headers  # type: ignore
    return _select_format(info)  # type: ignore


async def extract(video_url: str) -> tuple[str, str, dict[str, str]]:
    return await anyio.to_thread.run_sync(_extract, video_url)  # type: ignore


@app.get("/info")
async def info():
    return {"status": "ok"}


@app.get("/media")
async def media(url: str, request: Request, _=Depends(require_api_key)):
    def prepare() -> Tuple[str, Iterable[bytes]]:
        ydl_opts = {"quiet": True}
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)

            if info is None:
                raise ValueError("failed to extract info from URL")

            entries = info.get("entries", [])
            if entries and len(entries) == 0:
                raise ValueError(
                    "no downloadable content found - this may be a photo post"
                )

            if "url" in info and not info.get("is_live"):  # type: ignore
                direct = info["url"]  # type: ignore
                ext2 = info.get("ext", "mp4")  # type: ignore
                resp = ydl.urlopen(direct)
            else:
                direct, ext2, hdrs = _select_format(info)  # type: ignore[arg-type]
                req = urllib.request.Request(direct, headers=hdrs)
                resp = ydl.urlopen(req)

            def _iter() -> Iterable[bytes]:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    yield chunk

            return ext2, _iter()

    try:
        ext, reader_iter = await anyio.to_thread.run_sync(prepare)  # type: ignore
    except ValueError as exc:
        if "photo" in str(exc).lower():
            raise HTTPException(
                status_code=400,
                detail={"error": "photos_not_supported", "message": str(exc)},
            )
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    async def streamer():
        async for chunk in iterate_in_threadpool(reader_iter):
            yield chunk

    return StreamingResponse(streamer(), media_type=f"video/{ext}")


app.get("/video")(media)
