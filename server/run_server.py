#!/usr/bin/env python3
"""
Mneti Server — Production Startup Script
=============================================
Validates environment, then starts the Flask server via Gunicorn (Linux)
or Waitress (Windows) for production use.

Dev/testing: just run  python run_server.py --dev
"""

import sys
import os
import argparse
import logging

log = logging.getLogger("mneti.startup")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def validate_env():
    """Warn if insecure defaults are in use."""
    from config import Config
    warnings = []

    if "CHANGE_ME" in Config.SHARED_TOKEN:
        warnings.append("MNETI_TOKEN is using the default placeholder — set a strong secret!")
    if len(Config.SHARED_TOKEN) < 32:
        warnings.append("MNETI_TOKEN should be at least 32 characters long.")
    if Config.ADMIN_PASSWORD in ("admin_change_me", "admin", "password"):
        warnings.append("MNETI_ADMIN_PWD is using a weak/default password — change it!")
    if "192.168.1.100" in Config.SERVER_CALLBACK_URL:
        warnings.append("SERVER_CALLBACK_URL still points to placeholder IP. Update MNETI_CALLBACK_URL.")

    if warnings:
        print("\n" + "="*60)
        print("  ⚠  SECURITY WARNINGS — Please address before production:")
        for w in warnings:
            print(f"    • {w}")
        print("="*60 + "\n")
    return not warnings


def start_dev(port: int):
    """Flask dev server (single-threaded, not for production)."""
    log.info("Starting in DEV mode on port %d", port)
    from app import app
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)


def start_production(port: int, workers: int):
    """Start with Gunicorn (Linux) or Waitress (Windows)."""
    if sys.platform == "win32":
        try:
            from waitress import serve
            from app import app
            log.info("Starting with Waitress on port %d (%d threads)", port, workers)
            serve(app, host="0.0.0.0", port=port, threads=workers)
        except ImportError:
            log.warning("Waitress not installed. Falling back to Flask dev server.")
            log.warning("Install: pip install waitress")
            start_dev(port)
    else:
        cmd = [
            sys.executable, "-m", "gunicorn",
            "--bind", f"0.0.0.0:{port}",
            "--workers", str(workers),
            "--threads", "4",
            "--timeout", "30",
            "--access-logfile", "locator_access.log",
            "--error-logfile",  "locator_error.log",
            "--log-level", "info",
            "app:app",
        ]
        log.info("Starting Gunicorn: %s", " ".join(cmd))
        os.execv(sys.executable, cmd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mneti Server")
    parser.add_argument("--dev",     action="store_true", help="Run in development mode")
    parser.add_argument("--port",    type=int, default=5001)
    parser.add_argument("--workers", type=int, default=4, help="Gunicorn workers (production)")
    args = parser.parse_args()

    validate_env()

    if args.dev:
        start_dev(args.port)
    else:
        start_production(args.port, args.workers)