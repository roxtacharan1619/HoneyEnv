from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from honeyenv.demo_attack import simulate_attack
from honeyenv.generate import generate_honey_set
from honeyenv.inject import inject_folder
from honeyenv.paths import EXAMPLES_DIR, LAST_ALERT_PATH, REGISTRY_PATH, ROOT
from honeyenv.registry import list_tokens

console = Console()


def show_registry() -> None:
    tokens = list_tokens()
    if not tokens:
        console.print("[yellow]Registry is empty. Generate credentials first.[/yellow]")
        return
    table = Table(title=f"Honey registry ({REGISTRY_PATH})")
    table.add_column("Type")
    table.add_column("Env name")
    table.add_column("Prefix")
    table.add_column("Owner")
    table.add_column("Created")
    for token in tokens:
        table.add_row(
            str(token.get("type")),
            str(token.get("env_name")),
            str(token.get("prefix")) + "...",
            str(token.get("owner_name") or ""),
            str(token.get("created_at") or "")[:19],
        )
    console.print(table)


def show_last_alert() -> None:
    if not LAST_ALERT_PATH.exists():
        console.print("[yellow]No alerts yet.[/yellow]")
        return
    data = json.loads(LAST_ALERT_PATH.read_text(encoding="utf-8"))
    location = data.get("location") or "unknown"
    isp = data.get("isp") or data.get("org") or "unknown"
    extra = ""
    if data.get("socket_ip") and data.get("socket_ip") != data.get("ip"):
        extra += f"Socket IP: {data.get('socket_ip')}\n"
    if data.get("hostname"):
        extra += f"Hostname: {data.get('hostname')}\n"
    if data.get("note"):
        extra += f"{data.get('note')}\n"
    console.print(
        Panel.fit(
            f"[bold red]ALERT[/bold red] Fake {data.get('type')} key "
            f"[bold]{data.get('key_prefix')}[/bold] used by "
            f"public IP [bold]{data.get('ip')}[/bold]\n"
            f"Location: {location}\n"
            f"ISP / ASN: {isp} / {data.get('asn') or 'unknown'}\n"
            f"{extra}"
            f"Time: {data.get('at')}\n"
            f"UA: {data.get('user_agent')}\n"
            f"Discord: {data.get('discord', 'n/a')}",
            title="Last canary trip",
        )
    )


def do_generate() -> None:
    tokens = generate_honey_set(replace=False)
    console.print(f"[green]Ensured {len(tokens)} decoy credentials in the registry.[/green]")
    show_registry()


def do_inject() -> None:
    target = Path(Prompt.ask("Folder to inject (you must own it)", default=str(EXAMPLES_DIR)))
    results = inject_folder(target)
    if not results:
        console.print("[yellow]No .env files found.[/yellow]")
        return
    for path, status in results:
        color = "green" if status == "injected" else "cyan"
        console.print(f"[{color}]{status}[/{color}] {path}")


def do_listen() -> None:
    host = os.getenv("CANARY_HOST", "127.0.0.1")
    port = int(os.getenv("CANARY_PORT", "8080"))

    def _run() -> None:
        import uvicorn

        uvicorn.run("honeyenv.listener:app", host=host, port=port, reload=False, log_level="info")

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    console.print(
        Panel.fit(
            f"Canary listening on http://{host}:{port}\n"
            f"Health: GET /health   Trip: POST /canary\n"
            "Optional: ngrok http 8080  then set CANARY_PUBLIC_URL in .env",
            title="Listener",
        )
    )


def do_attack() -> None:
    prefer = Prompt.ask("Which decoy to 'use'", choices=["aws", "stripe", "github"], default="aws")
    try:
        result = simulate_attack(EXAMPLES_DIR / ".env.demo", prefer=prefer)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Attack simulation failed:[/red] {exc}")
        return
    console.print(f"Posted [bold]{result['env_name']}[/bold] to {result['url']}")
    console.print(result["body"])
    show_last_alert()


def banner() -> None:
    console.print(
        Panel.fit(
            "[bold yellow]HoneyEnv[/bold yellow] — decoy credentials, not exploits.\n"
            "Fake keys never call AWS, Stripe, or GitHub.\n"
            f"Project: {ROOT}",
            title="HoneyEnv",
        )
    )


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
    banner()
    actions = {
        "1": ("Generate decoy credentials", do_generate),
        "2": ("Inject honey keys into a folder", do_inject),
        "3": ("Start canary listener", do_listen),
        "4": ("Simulate attacker using a fake key", do_attack),
        "5": ("Show registry", show_registry),
        "6": ("Show last alert", show_last_alert),
        "q": ("Quit", None),
    }
    while True:
        console.print()
        for key, (label, _) in actions.items():
            console.print(f"  [bold]{key}[/bold]  {label}")
        choice = Prompt.ask("Choose", choices=list(actions), default="q")
        if choice == "q":
            return
        actions[choice][1]()


if __name__ == "__main__":
    main()
