"""MST Monitoring Agent - run on each authorized lab computer.

    python run_agent.py                 run the agent (uses config.json next to this file)
    python run_agent.py --check         send one heartbeat, show the result, and exit
    python run_agent.py --offline       print events on screen instead of sending them (testing)
"""

from __future__ import annotations

import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from mst_agent import VERSION
from mst_agent.agent import Agent
from mst_agent.config import ConfigError, load_config
from mst_agent.system_info import heartbeat_payload


def setup_logging(log_file: Path) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    file_handler = RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[console, file_handler])


def main() -> int:
    parser = argparse.ArgumentParser(description=f"MST Monitoring Agent {VERSION}")
    parser.add_argument("--config", default=str(Path(__file__).with_name("config.json")), help="path to config.json")
    parser.add_argument("--check", action="store_true", help="send one heartbeat to the MST server and exit")
    parser.add_argument("--offline", action="store_true", help="do not contact the server; print events instead")
    args = parser.parse_args()

    try:
        config = load_config(args.config, require_token=not args.offline)
    except ConfigError as error:
        print(error, file=sys.stderr)
        return 2
    setup_logging(config.log_file)

    agent = Agent(config, offline=args.offline)
    if args.check:
        print("This computer:", heartbeat_payload(config.server_url))
        ok = agent.send_heartbeat()
        agent.outbox.close()
        print("Heartbeat accepted by the MST server." if ok else "Heartbeat failed - see the message above.")
        return 0 if ok else 1

    print(f"MST Monitoring Agent {VERSION} - device {config.device_id}. Press Ctrl+C to stop.")
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
