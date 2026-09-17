# HoneyEnv

Defensive **canary tokens** for `.env` files. Attackers who dump environment variables often try the first AWS, Stripe, or GitHub key they find. HoneyEnv plants realistic **fake** keys next to real ones. If a decoy is sent to **your** canary listener, Discord fires a loud alert with the key prefix and source IP.

Fake keys never call AWS, Stripe, GitHub, or any vendor API. Inject only into folders you own.

## Setup

```powershell
cd "$env:USERPROFILE\Projects\HoneyEnv"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Create a Discord channel webhook (Server Settings → Integrations → Webhooks) and paste it into `.env`:

```
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
CANARY_HOST=127.0.0.1
CANARY_PORT=8080
```

Optional public URL for the 30-second demo:

```powershell
ngrok http 8080
```

Set `CANARY_PUBLIC_URL` in `.env` to the ngrok `https://...` origin (no path).

## 30-second demo

```powershell
python -m honeyenv
```

1. **Generate decoy credentials** (Faker names + AWS `AKIA…` / Stripe `sk_live_…` / GitHub `ghp_…` formats).
2. **Inject** into `examples/` — opens [examples/.env.demo](examples/.env.demo) with real-looking placeholders **and** three honey keys.
3. **Start canary listener**.
4. **Simulate attacker using a fake key** — POSTs the decoy to `/canary` only.
5. Discord (and the TUI) show: fake AWS key `AKIA...` used by IP `x.x.x.x`.

CLI equivalents:

```powershell
python -m honeyenv.generate
python -m honeyenv.inject examples
python -m honeyenv.listener
python -m honeyenv.demo_attack --prefer aws
```

## How it works

1. Generator writes unique decoys to `.honeyenv/registry.json`.
2. Injector finds `.env` / `.env.*` (skips `.env.example`), copies a `.honeyenv.bak` backup once, appends three honey vars if the `honeyenv-canary` marker is missing.
3. Listener `POST /canary` matches the presented key, reads `X-Forwarded-For` or the client host, posts a Discord embed, stores `.honeyenv/last_alert.json`.
4. Demo “attack” reads honey keys from the demo env file and hits your listener — not a cloud vendor.

## Out of scope

No env-dump malware, no real credential use, no scanning machines you do not own.
