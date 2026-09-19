import time
import threading
import uvicorn
from honeyenv.paths import EXAMPLES_DIR
from honeyenv.demo_attack import simulate_attack
from honeyenv.tui import show_last_alert

def start_server():
    uvicorn.run("honeyenv.listener:app", host="127.0.0.1", port=8080, log_level="warning")

if __name__ == "__main__":
    # Start canary listener in background thread
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    time.sleep(2)
    print("[+] Canary listener running on http://127.0.0.1:8080/canary")
    print("[*] Starting simulated attack with decoy AWS token...")
    result = simulate_attack(EXAMPLES_DIR / ".env.demo", prefer="aws")
    print(f"[+] Attack triggered: Posted {result['env_name']} to {result['url']}")
    print(f"[+] HTTP Status: {result['status_code']}")
    print(f"[+] Response: {result['body']}")
    time.sleep(1)
    print("\n--- Canary Alert Summary ---")
    show_last_alert()
