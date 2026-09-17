from __future__ import annotations

import argparse
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

from honeyenv.paths import EXAMPLES_DIR, MARKER, ROOT
from honeyenv.registry import list_tokens

load_dotenv(ROOT / ".env")

HONEY_NAMES = {
    "AWS_ACCESS_KEY_ID_PROD",
    "STRIPE_LIVE_SECRET_KEY",
    "GITHUB_TOKEN_CI",
}


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    in_honey = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if MARKER in line:
            in_honey = True
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip().strip('"').strip("'")
        if in_honey or name in HONEY_NAMES:
            values[name] = value
    return values


def pick_honey_key(env_path: Path, prefer: str = "aws") -> tuple[str, str]:
    parsed = parse_env(env_path) if env_path.exists() else {}
    prefer_name = {
        "aws": "AWS_ACCESS_KEY_ID_PROD",
        "stripe": "STRIPE_LIVE_SECRET_KEY",
        "github": "GITHUB_TOKEN_CI",
    }.get(prefer, prefer)
    if prefer_name in parsed:
        return prefer_name, parsed[prefer_name]
    if parsed:
        name = next(iter(parsed))
        return name, parsed[name]
    for token in list_tokens():
        if token.get("type") == prefer or prefer == token.get("env_name"):
            return str(token["env_name"]), str(token["value"])
    tokens = list_tokens()
    if not tokens:
        raise SystemExit("No honey keys found. Generate and inject first.")
    token = tokens[0]
    return str(token["env_name"]), str(token["value"])


def canary_url() -> str:
    public = os.getenv("CANARY_PUBLIC_URL", "").strip().rstrip("/")
    if public:
        return public + "/canary"
    host = os.getenv("CANARY_HOST", "127.0.0.1")
    port = os.getenv("CANARY_PORT", "8080")
    return f"http://{host}:{port}/canary"


def simulate_attack(env_path: Path | None = None, prefer: str = "aws") -> dict:
    path = env_path or (EXAMPLES_DIR / ".env.demo")
    name, key = pick_honey_key(path, prefer=prefer)
    url = canary_url()
    response = httpx.post(
        url,
        json={"key": key},
        headers={"User-Agent": "HoneyEnv-demo-attack/0.1"},
        timeout=10.0,
    )
    return {
        "env_name": name,
        "url": url,
        "status_code": response.status_code,
        "body": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate an attacker using a decoy key against YOUR canary (not AWS/Stripe)."
    )
    parser.add_argument("--env", type=Path, default=EXAMPLES_DIR / ".env.demo")
    parser.add_argument("--prefer", default="aws", choices=["aws", "stripe", "github"])
    args = parser.parse_args()
    result = simulate_attack(args.env, prefer=args.prefer)
    print(f"Posted {result['env_name']} to {result['url']}")
    print(f"HTTP {result['status_code']}: {result['body']}")


if __name__ == "__main__":
    main()
