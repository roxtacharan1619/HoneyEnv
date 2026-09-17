from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from honeyenv.generate import generate_honey_set
from honeyenv.paths import MARKER

SKIP_NAMES = {".env.example"}
HONEY_HEADER = (
    f"# {MARKER} decoy credentials — using these trips an alert. "
    "Do not treat as production secrets.\n"
)


def is_env_file(path: Path) -> bool:
    name = path.name
    if name in SKIP_NAMES:
        return False
    if name.endswith(".bak") or name.endswith(".honeyenv.bak"):
        return False
    return name == ".env" or name.startswith(".env.")


def find_env_files(folder: Path) -> list[Path]:
    folder = folder.resolve()
    if not folder.is_dir():
        raise FileNotFoundError(f"folder not found: {folder}")
    found: list[Path] = []
    for path in folder.rglob("*"):
        if path.is_file() and is_env_file(path):
            found.append(path)
    return sorted(found)


def already_honeyed(text: str) -> bool:
    return MARKER in text


def backup_env(path: Path) -> Path:
    bak = path.with_name(path.name + ".honeyenv.bak")
    if not bak.exists():
        shutil.copy2(path, bak)
    return bak


def honey_block(tokens: list[dict]) -> str:
    lines = [HONEY_HEADER.rstrip()]
    for token in tokens:
        owner = token.get("owner_name") or "unknown"
        company = token.get("company") or "unknown"
        lines.append(f"# decoy for {owner} / {company}")
        lines.append(f"{token['env_name']}={token['value']}")
    return "\n".join(lines) + "\n"


def inject_file(path: Path, tokens: list[dict]) -> str:
    original = path.read_text(encoding="utf-8")
    if already_honeyed(original):
        return "skipped"
    backup_env(path)
    body = original.rstrip() + "\n\n" + honey_block(tokens)
    path.write_text(body, encoding="utf-8")
    return "injected"


def inject_folder(folder: Path) -> list[tuple[Path, str]]:
    tokens = generate_honey_set(replace=False)
    results: list[tuple[Path, str]] = []
    for path in find_env_files(folder):
        results.append((path, inject_file(path, tokens)))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inject decoy HoneyEnv keys into .env files you own."
    )
    parser.add_argument("folder", type=Path, help="target folder (must be yours)")
    args = parser.parse_args()
    results = inject_folder(args.folder)
    if not results:
        print("No .env files found.")
        return
    for path, status in results:
        print(f"{status}: {path}")


if __name__ == "__main__":
    main()
