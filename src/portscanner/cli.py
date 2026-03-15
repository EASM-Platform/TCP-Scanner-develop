from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from .naabu_wrapper import NaabuRunner
from .pipeline import run_scan_pipeline
from .shadow_it import detect_new_assets, expand_target_cidrs, load_assets_state
from .tcp_connect_scanner import TCPConnectScanner, TCPConnectScanError

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "scan":
        return _run_scan_command(args)
    if args.command == "lab-up":
        return _run_lab_command(["compose", "-f", str(args.compose_file), "up", "-d", "--build"])
    if args.command == "lab-down":
        return _run_lab_command(["compose", "-f", str(args.compose_file), "down", "-v"])

    parser.error(f"Unknown command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Port scanner CLI")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a port scan")
    scan.add_argument("--target-cidr-file", type=Path, help="Path to a target_cidr.txt style file")
    scan.add_argument("--host", action="append", default=[], help="Host or IP to scan; repeatable")
    scan.add_argument("--backend", choices=["auto", "naabu", "tcp"], default="auto")
    scan.add_argument(
        "--ports",
        nargs="+",
        default=["1-65535"],
        help="Port specification for TCP backend or naabu override; accepts comma or space separated values",
    )
    scan.add_argument("--timeout", type=float, default=0.3, help="TCP connect timeout per port in seconds")
    scan.add_argument("--concurrency", type=int, default=512, help="TCP scan worker count")
    scan.add_argument("--rate", type=int, default=1000, help="naabu rate limit")
    scan.add_argument("--state-path", type=Path, default=PROJECT_ROOT / "assets_state.json")
    scan.add_argument("--json-out", type=Path, help="Optional JSON result output path")
    scan.add_argument("--nmap-output-dir", type=Path, default=PROJECT_ROOT / "nmap-output")
    scan.add_argument(
        "--skip-nmap",
        action="store_true",
        help="Skip service detection and return port-only results",
    )

    for name, help_text in (("lab-up", "Start the docker lab"), ("lab-down", "Stop the docker lab")):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--compose-file", type=Path, default=DEFAULT_COMPOSE_FILE)

    return parser


def _run_scan_command(args: argparse.Namespace) -> int:
    target_file = _resolve_target_file(args)
    previous_state = load_assets_state(args.state_path)
    scanner = _resolve_scanner(args)

    nmap_output_dir = args.nmap_output_dir
    if args.skip_nmap:
        nmap_output_dir = args.nmap_output_dir

    payloads = run_scan_pipeline(
        target_cidr_path=target_file,
        state_path=args.state_path,
        nmap_output_dir=nmap_output_dir,
        naabu_runner=scanner,
        nmap_scanner=None if not args.skip_nmap else _DisabledNmapScanner(),
        telegram_notifier=None,
        analysis_client=None,
    )

    current_state = {
        payload["target_ip"]: sorted(asset["port"] for asset in payload["assets"])
        for payload in payloads
    }
    if not current_state:
        # If nmap was skipped or unavailable, the pipeline still returns payloads. This branch
        # only handles the case where a scan found no open ports at all.
        current_state = scanner.scan(_load_hosts_for_summary(target_file))

    new_assets = detect_new_assets(current_state, previous_state)
    result = {
        "backend": scanner.__class__.__name__,
        "targets": sorted(current_state),
        "open_ports": current_state,
        "new_assets": [
            {"ip": event.ip, "port": event.port}
            for event in new_assets
        ],
    }

    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json_out:
        args.json_out.write_text(rendered, encoding="utf-8")

    return 0


def _resolve_target_file(args: argparse.Namespace) -> Path:
    if args.target_cidr_file:
        return args.target_cidr_file
    if args.host:
        target_file = PROJECT_ROOT / ".runtime-targets.txt"
        target_file.write_text("\n".join(args.host) + "\n", encoding="utf-8")
        return target_file
    raise SystemExit("At least one --host or --target-cidr-file is required")


def _resolve_scanner(args: argparse.Namespace) -> NaabuRunner | TCPConnectScanner:
    if args.backend == "naabu":
        return NaabuRunner(
            concurrency=min(args.concurrency, 50),
            rate=args.rate,
            timeout_seconds=600,
            port_spec=_normalize_port_spec(args.ports),
        )
    if args.backend == "tcp":
        return TCPConnectScanner(
            port_spec=_normalize_port_spec(args.ports),
            connect_timeout=args.timeout,
            concurrency=args.concurrency,
        )

    if shutil.which("naabu"):
        return NaabuRunner(
            concurrency=min(args.concurrency, 50),
            rate=args.rate,
            timeout_seconds=600,
            port_spec=_normalize_port_spec(args.ports),
        )

    LOGGER.warning("naabu not found; falling back to built-in TCP connect scanner")
    return TCPConnectScanner(
        port_spec=_normalize_port_spec(args.ports),
        connect_timeout=args.timeout,
        concurrency=args.concurrency,
    )


def _run_lab_command(docker_args: list[str]) -> int:
    command = ["docker", *docker_args]
    completed = subprocess.run(command, check=False)
    return completed.returncode


def _load_hosts_for_summary(target_file: Path) -> list[str]:
    return expand_target_cidrs(target_file)


def _normalize_port_spec(values: list[str]) -> str:
    chunks: list[str] = []
    for value in values:
        chunks.extend(part.strip() for part in str(value).split(",") if part.strip())
    return ",".join(chunks) or "1-65535"


class _DisabledNmapScanner:
    def scan_many(self, targets: dict[str, list[int]]) -> dict[str, Path]:
        return {}


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TCPConnectScanError as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        raise SystemExit(130)
