from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Iterable

LOGGER = logging.getLogger(__name__)


class NaabuExecutionError(RuntimeError):
    """Raised when naabu cannot be executed successfully."""


@dataclass(slots=True)
class NaabuRunner:
    binary_path: str = "naabu"
    concurrency: int = 50
    rate: int = 1000
    timeout_seconds: int = 600
    max_host_argument_length: int = 6000
    port_spec: str = "1-65535"

    def scan(self, hosts: Iterable[str]) -> dict[str, list[int]]:
        unique_hosts = list(dict.fromkeys(str(host) for host in hosts if str(host).strip()))
        if not unique_hosts:
            return {}

        aggregated: dict[str, set[int]] = {}
        for batch in _chunk_hosts(unique_hosts, self.max_host_argument_length):
            batch_results = self._scan_batch(batch)
            for ip, ports in batch_results.items():
                aggregated.setdefault(ip, set()).update(ports)

        return {ip: sorted(ports) for ip, ports in sorted(aggregated.items())}

    def _scan_batch(self, hosts: list[str]) -> dict[str, list[int]]:
        host_argument = ",".join(hosts)
        command = [
            self.binary_path,
            "-host",
            host_argument,
            "-p",
            self.port_spec,
            "-c",
            str(self.concurrency),
            "-rate",
            str(self.rate),
            "-silent",
            "-json",
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
            raise NaabuExecutionError("naabu scan timed out after 10 minutes") from exc
        except OSError as exc:
            raise NaabuExecutionError(f"Failed to execute naabu: {exc}") from exc

        if completed.stderr.strip():
            LOGGER.warning("naabu stderr: %s", completed.stderr.strip())

        if completed.returncode != 0:
            raise NaabuExecutionError(
                f"naabu exited with code {completed.returncode}: {completed.stderr.strip()}"
            )

        return _parse_naabu_output(completed.stdout)


def _parse_naabu_output(stdout: str) -> dict[str, list[int]]:
    results: dict[str, set[int]] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            LOGGER.warning("Skipping malformed naabu JSON line: %s", line)
            continue

        ip = payload.get("ip") or payload.get("host")
        port = payload.get("port")
        if not ip or port is None:
            LOGGER.warning("Skipping incomplete naabu result line: %s", line)
            continue

        try:
            normalized_port = int(port)
        except (TypeError, ValueError):
            LOGGER.warning("Skipping naabu result with non-numeric port: %s", line)
            continue

        results.setdefault(str(ip), set()).add(normalized_port)

    return {ip: sorted(ports) for ip, ports in sorted(results.items())}


def _chunk_hosts(hosts: list[str], max_host_argument_length: int) -> list[list[str]]:
    batches: list[list[str]] = []
    current_batch: list[str] = []
    current_length = 0

    for host in hosts:
        projected = current_length + len(host) + (1 if current_batch else 0)
        if current_batch and projected > max_host_argument_length:
            batches.append(current_batch)
            current_batch = [host]
            current_length = len(host)
            continue

        current_batch.append(host)
        current_length = projected

    if current_batch:
        batches.append(current_batch)

    return batches
