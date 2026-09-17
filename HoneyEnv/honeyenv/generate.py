from __future__ import annotations

import argparse
import re
import secrets
import string
import uuid
from datetime import datetime, timezone

from faker import Faker

from honeyenv.registry import list_tokens, upsert_tokens

AWS_RE = re.compile(r"^AKIA[A-Z0-9]{16}$")
STRIPE_RE = re.compile(r"^sk_live_[A-Za-z0-9]{24}$")
GITHUB_RE = re.compile(r"^ghp_[A-Za-z0-9]{36}$")

HONEY_ENV_NAMES = {
    "aws": "AWS_ACCESS_KEY_ID_PROD",
    "stripe": "STRIPE_LIVE_SECRET_KEY",
    "github": "GITHUB_TOKEN_CI",
}


def _alnum(length: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_aws_access_key() -> str:
    key = "AKIA" + _alnum(16, string.ascii_uppercase + string.digits)
    if not AWS_RE.match(key):
        raise ValueError("generated AWS key failed format check")
    return key


def generate_stripe_live_key() -> str:
    key = "sk_live_" + _alnum(24, string.ascii_letters + string.digits)
    if not STRIPE_RE.match(key):
        raise ValueError("generated Stripe key failed format check")
    return key


def generate_github_pat() -> str:
    key = "ghp_" + _alnum(36, string.ascii_letters + string.digits)
    if not GITHUB_RE.match(key):
        raise ValueError("generated GitHub token failed format check")
    return key


def generate_honey_set(*, replace: bool = False) -> list[dict]:
    existing = {t.get("type"): t for t in list_tokens()}
    fake = Faker()
    owner = fake.name()
    company = fake.company()
    created = datetime.now(timezone.utc).isoformat()

    factories = {
        "aws": generate_aws_access_key,
        "stripe": generate_stripe_live_key,
        "github": generate_github_pat,
    }
    tokens: list[dict] = []
    for kind, factory in factories.items():
        if not replace and kind in existing:
            tokens.append(existing[kind])
            continue
        value = factory()
        tokens.append(
            {
                "id": str(uuid.uuid4()),
                "type": kind,
                "env_name": HONEY_ENV_NAMES[kind],
                "value": value,
                "prefix": value[:8],
                "owner_name": owner,
                "company": company,
                "created_at": created,
            }
        )
    upsert_tokens(tokens)
    return tokens


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate decoy HoneyEnv credentials.")
    parser.add_argument("--replace", action="store_true", help="rotate existing decoys")
    args = parser.parse_args()
    tokens = generate_honey_set(replace=args.replace)
    for token in tokens:
        print(f"{token['env_name']}={token['prefix']}...  ({token['type']}, {token['owner_name']})")


if __name__ == "__main__":
    main()
