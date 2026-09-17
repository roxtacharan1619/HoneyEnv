from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HONEY_DIR = ROOT / ".honeyenv"
REGISTRY_PATH = HONEY_DIR / "registry.json"
LAST_ALERT_PATH = HONEY_DIR / "last_alert.json"
EXAMPLES_DIR = ROOT / "examples"
MARKER = "honeyenv-canary"


def ensure_honey_dir() -> Path:
    HONEY_DIR.mkdir(parents=True, exist_ok=True)
    return HONEY_DIR
