"""Entry point: `python3 -m chaoslab` starts the Chaos Monkey controller."""
from __future__ import annotations

import argparse
import atexit
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from logging.handlers import RotatingFileHandler
from typing import List

from . import __version__
from .engine import Engine
from .fleet import Fleet
from .server import BUILDS, App, local_addresses, serve
from .store import Store

LOG = logging.getLogger("chaoslab")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_agents(dist: str) -> int:
    """Cross-compile the endpoint agent for every platform the dashboard serves. Needs Go once,
    on a machine that has it; the result is three self-contained files."""
    go = shutil.which("go")
    if not go:
        print("Go is not installed here. Build on any machine that has Go 1.23+ (make agents) and copy the\n"
              f"three files in dist/ to {dist}, or use a release bundle, which already contains them.",
              file=sys.stderr)
        return 1
    os.makedirs(dist, exist_ok=True)
    for name, (goos, goarch) in BUILDS.items():
        env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0")
        out = os.path.join(dist, name)
        print(f"building {name} …", flush=True)
        done = subprocess.run([go, "build", "-trimpath", "-ldflags", "-s -w", "-o", out, "."],
                              cwd=os.path.join(ROOT, "agent"), env=env, timeout=600)
        if done.returncode != 0:
            return done.returncode
    print(f"agents written to {dist}")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chaoslab",
        description="Chaos Monkey controller: breaks SD-WAN lab links on purpose and measures what endpoint "
                    "traffic saw. WARNING: outside --demo this disrupts real appliances and lab fabric. "
                    "Lab and authorised change windows only. Provided as is, without warranty.")
    p.add_argument("command", nargs="?", default="serve", choices=("serve", "build-agents"))
    p.add_argument("--host", default="0.0.0.0", help="address to listen on (default: all, endpoints must reach it)")
    p.add_argument("--port", type=int, default=1666)
    p.add_argument("--data", default=os.environ.get("CHAOSLAB_DATA", os.path.join(ROOT, "data")),
                   help="where history, settings and credentials are kept")
    p.add_argument("--dist", default=os.path.join(ROOT, "dist"), help="where the agent builds live")
    p.add_argument("--demo", action="store_true", help="simulated lab and endpoints; nothing real is contacted")
    p.add_argument("--keep-days", type=float, default=14, help="days of per-second measurements to keep")
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--log-file", help="also log to this file (rotating, 10 MB x 5)")
    p.add_argument("--debug", action="store_true")
    return p


def main(argv: List[str] = None) -> int:
    args = parser().parse_args(argv)
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(RotatingFileHandler(args.log_file, maxBytes=10 << 20, backupCount=5))
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    if args.command == "build-agents":
        return build_agents(args.dist)

    data_dir = os.path.join(args.data, "demo") if args.demo else args.data
    store = Store(data_dir)
    fleet = Fleet(store)
    engine = Engine(store, fleet)
    app = App(store, fleet, engine, dist=args.dist, demo=args.demo, port=args.port,
              password=os.environ.get("CHAOSLAB_PASSWORD", ""))
    if args.demo:
        from .drivers.sim import SimLab, run_sim_fleet
        lab = SimLab()
        engine.set_driver("sim", lab)
        run_sim_fleet(lab, fleet)
    else:
        app.load_connections()

    def restore(*_: object) -> None:
        errors = engine.restore_all()
        for error in errors:
            LOG.error("RESTORE FAILED: %s", error)

    def on_signal(signum: int, _frame: object) -> None:
        LOG.warning("received %s: restoring anything held and exiting", signal.Signals(signum).name)
        engine.stop()
        restore()
        os._exit(128 + signum)

    atexit.register(restore)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        serve(app, args.host, args.port)
    except OSError as exc:
        LOG.error("cannot listen on %s:%d: %s", args.host, args.port, exc)
        return 1

    def housekeeping() -> None:
        while True:
            try:
                store.prune(args.keep_days)
            except Exception:
                LOG.exception("pruning failed")
            time.sleep(3600)
    threading.Thread(target=housekeeping, daemon=True, name="prune").start()

    addrs = local_addresses() if args.host in ("0.0.0.0", "::") else [args.host]
    missing = [b["file"] for b in app.builds() if b["size"] is None]
    line = "=" * 72
    print(line)
    print(f" Chaos Monkey {__version__}" + ("   [DEMO: simulated lab, nothing real is contacted]" if args.demo else ""))
    print(f" Dashboard:  http://localhost:{args.port}/")
    for a in addrs:
        print(f"             http://{a}:{args.port}/")
    if app.password:
        print(" Access:     password required (CHAOSLAB_PASSWORD)")
    else:
        print(" Access:     OPEN to anyone who can reach this port. Set CHAOSLAB_PASSWORD to require a password.")
    if addrs:
        print(f" Add an endpoint (Linux):    curl -fsSL 'http://{addrs[0]}:{args.port}/install.sh?token={fleet.join_token}' | sudo sh")
        print(f" Add an endpoint (Windows):  irm 'http://{addrs[0]}:{args.port}/install.ps1?token={fleet.join_token}' | iex")
    if missing:
        print(f" NOTE: agent builds missing ({', '.join(missing)}).")
        print("       Run:  python3 -m chaoslab build-agents     (needs Go once; or use a release bundle)")
    print(f" Data:       {data_dir}")
    print(line, flush=True)
    if not args.no_browser:
        try:
            webbrowser.open(f"http://localhost:{args.port}/")
        except webbrowser.Error:
            pass
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
