"""
Mneti Server Configuration
Edit this file or server/.env before deployment.
"""

import os
import secrets
import socket


def load_env():
    """Load .env file manually into os.environ to avoid external dependencies."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(base_dir, ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip()
                        # Strip single or double quotes
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        os.environ[key] = val
        except Exception as e:
            print(f"Warning: Failed to load .env file: {e}")


# Load environment variables from .env
load_env()


def get_lan_ip() -> str:
    """Dynamically discover the server's primary LAN IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not send actual traffic, just routes socket via active interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


class Config:
    # ── Shared secret (must match client config.json) ─────────────────────────
    SHARED_TOKEN: str = os.environ.get(
        "MNETI_TOKEN",
        "CHANGE_ME_USE_A_LONG_RANDOM_SECRET_AT_LEAST_32_CHARS"
    )

    # ── Admin dashboard password ──────────────────────────────────────────────
    ADMIN_PASSWORD: str = os.environ.get("MNETI_ADMIN_PWD", "admin_change_me")

    # ── Flask session secret ──────────────────────────────────────────────────
    FLASK_SECRET: str = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

    # ── Network ports ─────────────────────────────────────────────────────────
    UDP_PORT: int = 5000          # Broadcast discovery requests
    HTTP_PORT: int = 5001         # Flask server + client callback

    # ── Discovery timing ──────────────────────────────────────────────────────
    DISCOVERY_TIMEOUT: int = 5    # Seconds to collect responses
    RESULT_TTL: int = 3600        # Seconds to keep results in memory

    # ── Trusted networks (internal subnets only) ──────────────────────────────
    TRUSTED_NETWORKS: list = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ]

    # ── UDP broadcast settings ────────────────────────────────────────────────
    UDP_BROADCAST_ADDR: str = "255.255.255.255"
    UDP_TTL: int = 4              # Limit broadcast hop count where supported

    # ── Flask server host/port for client callback ────────────────────────────
    # Clients will POST their responses here
    SERVER_CALLBACK_URL: str = os.environ.get(
        "MNETI_CALLBACK_URL",
        f"http://{get_lan_ip()}:{HTTP_PORT}/api/report"
    )
