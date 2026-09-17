from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from honeyenv.paths import LAST_ALERT_PATH, ROOT, ensure_honey_dir
from honeyenv.registry import find_token

load_dotenv(ROOT / ".env")

app = FastAPI(title="HoneyEnv Canary", version="0.1.0")


async def extract_presented(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    if auth.lower().startswith("aws "):
        return auth.split()[-1].strip()
    try:
        data = await request.json()
    except Exception:
        data = {}
    if isinstance(data, dict):
        for field in ("key", "token", "aws_access_key_id", "access_key"):
            value = data.get(field)
            if value:
                return str(value).strip()
    return ""


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def mask_key(value: str) -> str:
    if len(value) <= 8:
        return value + "..."
    return value[:8] + "..."


def write_last_alert(payload: dict[str, Any]) -> None:
    ensure_honey_dir()
    LAST_ALERT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def notify_discord(alert: dict[str, Any]) -> None:
    webhook = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook:
        return
    kind = str(alert.get("type") or "key").upper()
    prefix = alert.get("key_prefix")
    ip = alert.get("ip")
    description = (
        f"ALERT: Fake {kind} key `{prefix}` was just used by IP `{ip}`!\n"
        f"User-Agent: {alert.get('user_agent')}\n"
        f"Time (UTC): {alert.get('at')}"
    )
    embed = {
        "title": "HoneyEnv canary tripped",
        "description": description,
        "color": 16711680,
    }
    try:
        httpx.post(webhook, json={"embeds": [embed]}, timeout=10.0).raise_for_status()
        alert["discord"] = "sent"
    except Exception as exc:  # noqa: BLE001 — surface webhook errors in last_alert
        alert["discord"] = f"failed: {exc}"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/canary")
async def canary(request: Request) -> JSONResponse:
    presented = await extract_presented(request)
    token = find_token(presented)
    if not token:
        return JSONResponse({"ok": False, "error": "unknown decoy"}, status_code=404)

    alert = {
        "at": datetime.now(timezone.utc).isoformat(),
        "type": token.get("type"),
        "env_name": token.get("env_name"),
        "key_prefix": mask_key(str(token.get("value") or presented)),
        "ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "unknown"),
        "token_id": token.get("id"),
    }
    notify_discord(alert)
    write_last_alert(alert)
    return JSONResponse({"ok": True, "alert": alert})


def main() -> None:
    import uvicorn

    host = os.getenv("CANARY_HOST", "127.0.0.1")
    port = int(os.getenv("CANARY_PORT", "8080"))
    uvicorn.run("honeyenv.listener:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
