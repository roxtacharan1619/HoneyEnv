from __future__ import annotations

import ipaddress
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

_IP_LOOKUP_URL = "https://ipwho.is/{ip}"


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


def _parse_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().strip("[]")
    if candidate.startswith("::ffff:"):
        candidate = candidate[7:]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return ip in {"localhost", "unknown"}


def _is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )


def _ips_from_forwarded(header: str | None) -> list[str]:
    if not header:
        return []
    found: list[str] = []
    for part in header.split(","):
        ip = _parse_ip(part)
        if ip:
            found.append(ip)
    return found


def peer_socket_ip(request: Request) -> str:
    if request.client and request.client.host:
        return _parse_ip(request.client.host) or request.client.host
    return "unknown"


def presented_ips(request: Request) -> list[tuple[str, str]]:
    """Ordered (ip, source) candidates from proxy headers, then the TCP peer."""
    candidates: list[tuple[str, str]] = []
    for header, source in (
        ("cf-connecting-ip", "cf-connecting-ip"),
        ("true-client-ip", "true-client-ip"),
        ("x-real-ip", "x-real-ip"),
        ("x-forwarded-for", "x-forwarded-for"),
        ("forwarded", "forwarded"),
    ):
        raw = request.headers.get(header)
        if header == "forwarded" and raw:
            for part in raw.split(","):
                for token in part.split(";"):
                    token = token.strip()
                    if token.lower().startswith("for="):
                        ip = _parse_ip(token[4:].strip().strip('"'))
                        if ip:
                            candidates.append((ip, source))
            continue
        for ip in _ips_from_forwarded(raw):
            candidates.append((ip, source))
    peer = peer_socket_ip(request)
    candidates.append((peer, "socket"))
    return candidates


def lookup_egress_public_ip() -> str | None:
    """Public IP of this host (used when the client is localhost)."""
    try:
        response = httpx.get("https://api.ipify.org", timeout=4.0)
        response.raise_for_status()
        return _parse_ip(response.text)
    except Exception:
        return None


def resolve_attacker_ip(request: Request) -> dict[str, Any]:
    candidates = presented_ips(request)
    peer = peer_socket_ip(request)
    public = next(((ip, src) for ip, src in candidates if _is_public_ip(ip)), None)
    if public:
        ip, source = public
        return {"ip": ip, "socket_ip": peer, "ip_source": source}

    first_ip, first_source = candidates[0]
    if _is_loopback(peer) or _is_loopback(first_ip):
        egress = lookup_egress_public_ip()
        if egress:
            return {
                "ip": egress,
                "socket_ip": peer,
                "ip_source": "egress-public",
                "note": "Client was localhost; alert uses this machine's public IP.",
            }
    return {"ip": first_ip, "socket_ip": peer, "ip_source": first_source}


def enrich_ip(ip: str) -> dict[str, Any]:
    if not _is_public_ip(ip):
        return {"geo": "private or local address"}
    try:
        response = httpx.get(_IP_LOOKUP_URL.format(ip=ip), timeout=4.0)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:  # noqa: BLE001
        return {"geo": f"lookup failed: {exc}"}
    if not data.get("success", True):
        return {"geo": data.get("message") or "lookup failed"}
    conn = data.get("connection") or {}
    tz = data.get("timezone") or {}
    place = ", ".join(
        part for part in (data.get("city"), data.get("region"), data.get("country")) if part
    )
    asn_num = conn.get("asn")
    asn = f"AS{asn_num} {conn.get('org') or ''}".strip() if asn_num else conn.get("org")
    return {
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "isp": conn.get("isp"),
        "org": conn.get("org"),
        "asn": asn,
        "timezone": tz.get("id") if isinstance(tz, dict) else tz,
        "location": place or None,
        "hostname": data.get("domain") or conn.get("domain"),
    }


def attacker_request_details(request: Request) -> dict[str, Any]:
    details: dict[str, Any] = {
        "user_agent": request.headers.get("user-agent", "unknown"),
        "method": request.method,
        "path": request.url.path,
        "host": request.headers.get("host", "unknown"),
    }
    optional = {
        "referer": request.headers.get("referer"),
        "origin": request.headers.get("origin"),
        "accept_language": request.headers.get("accept-language"),
        "cf_ipcountry": request.headers.get("cf-ipcountry"),
    }
    details.update({key: value for key, value in optional.items() if value})
    return details


def attacker_profile(request: Request) -> dict[str, Any]:
    resolved = resolve_attacker_ip(request)
    ip = str(resolved["ip"])
    geo = enrich_ip(ip)
    profile = {
        **resolved,
        **attacker_request_details(request),
        **{k: v for k, v in geo.items() if v},
    }
    return profile


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
    location = alert.get("location") or "unknown"
    isp = alert.get("isp") or alert.get("org") or "unknown"
    asn = alert.get("asn") or "unknown"
    hostname = alert.get("hostname") or "unknown"
    socket_ip = alert.get("socket_ip")
    lines = [
        f"ALERT: Fake {kind} key `{prefix}` was just used.",
        f"Public IP: `{ip}` ({alert.get('ip_source', 'unknown')})",
        f"Location: {location}",
        f"ISP / ASN: {isp} / {asn}",
        f"Hostname: {hostname}",
        f"User-Agent: {alert.get('user_agent')}",
        f"Time (UTC): {alert.get('at')}",
    ]
    if socket_ip and socket_ip != ip:
        lines.insert(2, f"Socket IP: `{socket_ip}`")
    if alert.get("note"):
        lines.append(str(alert["note"]))
    if alert.get("accept_language"):
        lines.append(f"Accept-Language: {alert['accept_language']}")
    description = "\n".join(lines)
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

    profile = attacker_profile(request)
    alert = {
        "at": datetime.now(timezone.utc).isoformat(),
        "type": token.get("type"),
        "env_name": token.get("env_name"),
        "key_prefix": mask_key(str(token.get("value") or presented)),
        "token_id": token.get("id"),
        **profile,
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
