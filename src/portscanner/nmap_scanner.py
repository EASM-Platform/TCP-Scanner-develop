from __future__ import annotations

import logging
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

LOGGER = logging.getLogger(__name__)


class NmapExecutionError(RuntimeError):
    """Raised when a single nmap scan fails."""


class NmapBatchError(RuntimeError):
    """Raised when one or more hosts fail during a parallel nmap run."""

    def __init__(self, errors: dict[str, str], completed: dict[str, Path]) -> None:
        super().__init__(f"Nmap completed with {len(errors)} failed host(s)")
        self.errors = errors
        self.completed = completed


@dataclass(slots=True)
class NmapScanner:
    output_dir: Path | str
    binary_path: str = "nmap"
    max_workers: int = 5
    timeout_seconds: int = 300

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)

    def scan_host(self, ip: str, ports: Sequence[int]) -> Path:
        normalized_ports = _format_ports(ports)
        output_path = self.output_dir / f"{_safe_filename(ip)}.xml"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        command = [
            self.binary_path,
            "-sV",
            "-sC",
            "-Pn",
            "-T4",
            "-p",
            normalized_ports,
            ip,
            "-oX",
            str(output_path),
        ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise NmapExecutionError(f"nmap scan timed out for {ip} after 5 minutes") from exc
        except OSError as exc:
            raise NmapExecutionError(f"Failed to execute nmap for {ip}: {exc}") from exc

        if completed.stderr.strip():
            LOGGER.warning("nmap stderr for %s: %s", ip, completed.stderr.strip())

        if completed.returncode != 0:
            raise NmapExecutionError(
                f"nmap exited with code {completed.returncode} for {ip}: {completed.stderr.strip()}"
            )

        if not output_path.exists():
            raise NmapExecutionError(f"nmap did not create an XML report for {ip}: {output_path}")

        return output_path

    def scan_many(self, targets: Mapping[str, Sequence[int]]) -> dict[str, Path]:
        if not targets:
            return {}

        completed: dict[str, Path] = {}
        errors: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {
                executor.submit(self.scan_host, ip, ports): ip
                for ip, ports in targets.items()
            }
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    completed[ip] = future.result()
                except NmapExecutionError as exc:
                    LOGGER.error("nmap scan failed for %s: %s", ip, exc)
                    errors[ip] = str(exc)

        if errors:
            raise NmapBatchError(errors=errors, completed=completed)

        return completed


def _format_ports(ports: Sequence[int]) -> str:
    normalized = sorted({int(port) for port in ports})
    if not normalized:
        raise NmapExecutionError("At least one open port is required for nmap scanning")
    return ",".join(str(port) for port in normalized)


def _safe_filename(ip: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", ip)
