from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from honeyenv.paths import REGISTRY_PATH, ensure_honey_dir

Token = dict[str, Any]


def load_registry() -> dict[str, Any]:
    if not REGISTRY_PATH.exists():
        return {"tokens": []}
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def save_registry(data: dict[str, Any]) -> None:
    ensure_honey_dir()
    REGISTRY_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def list_tokens() -> list[Token]:
    return list(load_registry().get("tokens") or [])


def upsert_tokens(tokens: list[Token]) -> None:
    data = load_registry()
    by_env = {t.get("env_name"): t for t in data.get("tokens") or []}
    for token in tokens:
        by_env[token["env_name"]] = token
    data["tokens"] = list(by_env.values())
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_registry(data)


def find_token(presented: str) -> Token | None:
    presented = (presented or "").strip()
    if not presented:
        return None
    for token in list_tokens():
        value = str(token.get("value") or "")
        prefix = str(token.get("prefix") or "")
        if value and presented == value:
            return token
        if prefix and presented.startswith(prefix):
            return token
        if value and presented.startswith(value[:8]):
            return token
    return None
