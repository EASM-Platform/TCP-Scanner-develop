from __future__ import annotations

import logging
import socket
import threading
from dataclasses import dataclass
from queue import Empty, Queue
from typing import Iterable

LOGGER = logging.getLogger(__name__)


class TCPConnectScanError(RuntimeError):
    """Raised when the built-in TCP connect scanner cannot execute safely."""


@dataclass(slots=True)
class TCPConnectScanner:
    port_spec: str = "1-65535"
    connect_timeout: float = 0.3
    concurrency: int = 512

    def scan(self, hosts: Iterable[str]) -> dict[str, list[int]]:
        unique_hosts = list(dict.fromkeys(str(host) for host in hosts if str(host).strip()))
        ports = parse_port_spec(self.port_spec)
        if not unique_hosts or not ports:
            return {}

        results: dict[str, list[int]] = {}
        for host in unique_hosts:
            open_ports = self._scan_host(host, ports)
            if open_ports:
                results[host] = open_ports

        return results

    def _scan_host(self, host: str, ports: list[int]) -> list[int]:
        port_queue: Queue[int] = Queue()
        for port in ports:
            port_queue.put(port)

        open_ports: list[int] = []
        open_ports_lock = threading.Lock()

        def worker() -> None:
            while True:
                try:
                    port = port_queue.get_nowait()
                except Empty:
                    return

                try:
                    if _is_port_open(host, port, self.connect_timeout):
                        with open_ports_lock:
                            open_ports.append(port)
                finally:
                    port_queue.task_done()

        thread_count = min(self.concurrency, len(ports))
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(thread_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        return sorted(open_ports)


def parse_port_spec(port_spec: str) -> list[int]:
    ports: set[int] = set()
    for raw_chunk in port_spec.split(","):
        chunk = raw_chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start = _normalize_port(start_text)
            end = _normalize_port(end_text)
            if start > end:
                raise TCPConnectScanError(f"Invalid port range: {chunk}")
            ports.update(range(start, end + 1))
            continue
        ports.add(_normalize_port(chunk))

    return sorted(ports)


def _normalize_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise TCPConnectScanError(f"Invalid port value: {value}") from exc

    if port < 1 or port > 65535:
        raise TCPConnectScanError(f"Port out of range: {port}")
    return port


def _is_port_open(host: str, port: int, timeout: float) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
        except OSError as exc:
            LOGGER.debug("TCP connect failed for %s:%s: %s", host, port, exc)
            return False
    return result == 0
