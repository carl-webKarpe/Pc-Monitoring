"""MST Monitoring Agent - run on each authorized lab computer.

    python run_agent.py                 run the agent (uses config.json next to this file)
    python run_agent.py --check         send one heartbeat, show the result, and exit
    python run_agent.py --offline       print events on screen instead of sending them (testing)
    python run_agent.py --enroll KEY    add this PC with an enrollment key (Computers > Add Computers); finds
                                        the server on the network, or give it: --server 192.168.0.61
    python run_agent.py --find-server   search the network for the MST server and save its new address
    python run_agent.py --import-config use the config.json downloaded from Computers > Add Computers > One PC
                                        (found in this folder or in Downloads; no enrollment key needed)
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
from mst_agent.enroll import EnrollError, enroll
from mst_agent.setup_helper import downloads_folder, find_downloaded_config, import_config, is_enrolled
from mst_agent.single_instance import AlreadyRunning, SingleInstance
from mst_agent.system_info import heartbeat_payload


def setup_logging(log_file: Path) -> None:
    # The Windows console may not support every character in a file name; never fail on it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    file_handler = RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[console, file_handler])


def import_downloaded_config(config_path: Path, source: str) -> int:
    found = Path(source) if source else find_downloaded_config(config_path.parent, downloads_folder())
    if found is None or not found.is_file():
        print("No config.json from the MST website was found in this folder or in Downloads.")
        return 1
    if found.resolve() == config_path.resolve():
        return 0 if is_enrolled(config_path) else 1
    try:
        data = import_config(found, config_path)
    except OSError as error:
        print(f"Could not copy {found} to {config_path}: {error}", file=sys.stderr)
        return 1
    if not is_enrolled(config_path):
        print(f"{found} is not a config.json from Add Computers > One PC (no device token).", file=sys.stderr)
        return 1
    print(f"Using {found} (device {data['device_id']}, server {data['server_url']}).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=f"MST Monitoring Agent {VERSION}")
    parser.add_argument("--config", default=str(Path(__file__).with_name("config.json")), help="path to config.json")
    parser.add_argument("--check", action="store_true", help="send one heartbeat to the MST server and exit")
    parser.add_argument("--offline", action="store_true", help="do not contact the server; print events instead")
    parser.add_argument("--enroll", metavar="KEY", help="enroll this PC with an enrollment key and write config.json")
    parser.add_argument("--server", help="with --enroll: the MST server address (default: search this network)")
    parser.add_argument("--data-dir", help="with --enroll: folder for the queue, log and quarantine (e.g. %%LOCALAPPDATA%%\\MST-Agent)")
    parser.add_argument("--find-server", action="store_true", help="search the network for the MST server and update config.json")
    parser.add_argument("--import-config", nargs="?", const="", metavar="FILE",
                        help="use a config.json downloaded from Add Computers > One PC (default: search this folder and Downloads)")
    parser.add_argument("--is-enrolled", action="store_true", help="exit 0 when config.json has this PC's device token")
    args = parser.parse_args()

    if args.is_enrolled:
        return 0 if is_enrolled(Path(args.config)) else 1
    if args.import_config is not None:
        return import_downloaded_config(Path(args.config), args.import_config)

    if args.enroll:
        print("Enrolling this PC" + (f" with the MST server {args.server}..." if args.server else "; searching this network for the MST server..."))
        try:
            result = enroll(args.enroll, Path(args.config), Path(__file__).with_name("config.example.json"), args.server, args.data_dir)
        except EnrollError as error:
            print(f"Enrollment failed: {error}", file=sys.stderr)
            return 1
        print(f"Enrolled as {result['deviceId']}{' (this PC was enrolled before; it keeps its device ID)' if result['reused'] else ''}. "
              f"Server: {result['serverUrl']}")
        args.check = True

    try:
        config = load_config(args.config, require_token=not args.offline)
    except ConfigError as error:
        print(error, file=sys.stderr)
        return 2
    setup_logging(config.log_file)

    if not (args.check or args.find_server):
        # One agent per computer: a second copy (e.g. started twice) would report every file twice.
        lock = SingleInstance(config.queue_file.with_name("mst_agent.lock"))
        try:
            lock.acquire()
        except AlreadyRunning as error:
            print(error)
            return 3

    agent = Agent(config, offline=args.offline)
    if args.find_server:
        found = agent.rediscover(force=True)
        print(f"MST server: {config.server_url}" + (" (new address saved in config.json)" if found else ""))
        args.check = True
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
