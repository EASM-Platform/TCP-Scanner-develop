from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

import requests

LOGGER = logging.getLogger(__name__)


class AssetStateError(RuntimeError):
    """Raised when state or target files cannot be parsed safely."""


class TelegramNotificationError(RuntimeError):
    """Raised when Telegram delivery fails."""


@dataclass(frozen=True, slots=True)
class NewAssetEvent:
    ip: str
    port: int


def expand_target_cidrs(path: str | Path) -> list[str]:
    """Expand a text file of CIDRs into a deduplicated host list."""

    hosts: dict[str, None] = {}
    for network in _load_target_networks(path):
        if network.num_addresses == 1:
            hosts[str(network.network_address)] = None
            continue

        for host in network.hosts():
            hosts[str(host)] = None

    return sorted(hosts, key=_ip_sort_key)


def load_assets_state(path: str | Path) -> dict[str, set[int]]:
    """Load the previous scan state. Missing files return an empty state."""

    state_path = Path(path)
    if not state_path.exists():
        return {}

    try:
        raw_state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssetStateError(f"Failed to load asset state from {state_path}") from exc

    if not isinstance(raw_state, dict):
        raise AssetStateError(f"Asset state must be a JSON object: {state_path}")

    normalized: dict[str, set[int]] = {}
    for ip, ports in raw_state.items():
        if not isinstance(ip, str) or not isinstance(ports, list):
            raise AssetStateError(f"Invalid asset state entry for {ip!r} in {state_path}")
        normalized[ip] = {int(port) for port in ports}
    return normalized


def save_assets_state(path: str | Path, state: Mapping[str, Iterable[int]]) -> None:
    """Persist the latest scan state using an atomic file replacement."""

    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_path.with_suffix(f"{state_path.suffix}.tmp")

    payload = {
        ip: sorted({int(port) for port in ports})
        for ip, ports in sorted(state.items(), key=lambda item: _ip_sort_key(item[0]))
    }
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(state_path)


def detect_new_assets(
    current_results: Mapping[str, Iterable[int]],
    previous_state: Mapping[str, Iterable[int]],
) -> list[NewAssetEvent]:
    """Compare current results with the previous state and return new IP/port combinations."""

    previous = {
        ip: {int(port) for port in ports}
        for ip, ports in previous_state.items()
    }
    current = {
        ip: {int(port) for port in ports}
        for ip, ports in current_results.items()
    }

    events: list[NewAssetEvent] = []
    for ip, ports in current.items():
        prior_ports = previous.get(ip, set())
        for port in sorted(ports - prior_ports):
            events.append(NewAssetEvent(ip=ip, port=port))

    return sorted(events, key=lambda event: (_ip_sort_key(event.ip), event.port))


@dataclass(slots=True)
class TelegramNotifier:
    bot_token: str
    chat_id: str
    timeout_seconds: float = 10.0
    api_base: str = "https://api.telegram.org"
    session: requests.Session | None = None

    def send_events(self, events: Iterable[NewAssetEvent]) -> None:
        errors: list[str] = []
        for event in events:
            try:
                self.send_event(event)
            except TelegramNotificationError as exc:
                LOGGER.error("Telegram notification failed for %s:%s: %s", event.ip, event.port, exc)
                errors.append(str(exc))

        if errors:
            raise TelegramNotificationError("; ".join(errors))

    def send_event(self, event: NewAssetEvent) -> None:
        client = self.session or requests.Session()
        url = f"{self.api_base}/bot{self.bot_token}/sendMessage"
        message = f"[신규 자산 발견] IP: {event.ip}, Port: {event.port} 가 새로 활성화되었습니다."

        try:
            response = client.post(
                url,
                json={"chat_id": self.chat_id, "text": message},
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise TelegramNotificationError(f"HTTP error while sending Telegram alert: {exc}") from exc
        except ValueError as exc:
            raise TelegramNotificationError("Telegram returned a non-JSON response") from exc

        if not payload.get("ok", False):
            raise TelegramNotificationError(f"Telegram API rejected the message: {payload}")


def _load_target_networks(path: str | Path) -> list[ipaddress._BaseNetwork]:
    target_path = Path(path)
    try:
        lines = target_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AssetStateError(f"Failed to read target CIDR file: {target_path}") from exc

    networks: list[ipaddress._BaseNetwork] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError as exc:
            raise AssetStateError(
                f"Invalid CIDR entry at {target_path}:{line_number}: {line}"
            ) from exc

    return networks


def _ip_sort_key(value: str) -> tuple[int, int]:
    parsed = ipaddress.ip_address(value)
    return parsed.version, int(parsed)
