from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

import requests


class AnalysisApiError(RuntimeError):
    """Raised when the downstream analysis API cannot be called successfully."""


def build_analysis_payload(
    *,
    scan_id: str,
    timestamp: datetime,
    target_ip: str,
    assets: Iterable[Mapping[str, Any]],
    new_assets: set[tuple[str, int]] | None = None,
) -> dict[str, Any]:
    normalized_new_assets = new_assets or set()
    payload_assets: list[dict[str, Any]] = []

    for asset in assets:
        port = int(asset["port"])
        payload_assets.append(
            {
                "port": port,
                "protocol": asset.get("protocol", "tcp"),
                "service_name": asset.get("service_name", "unknown"),
                "version": asset.get("version"),
                "banner_data": dict(asset.get("banner_data", {})),
                "is_new": (target_ip, port) in normalized_new_assets,
            }
        )

    return {
        "scan_id": scan_id,
        "timestamp": _format_timestamp(timestamp),
        "target_ip": target_ip,
        "assets": payload_assets,
    }


@dataclass(slots=True)
class AnalysisApiClient:
    endpoint_url: str
    timeout_seconds: float = 15.0
    session: requests.Session | None = None

    def post_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        client = self.session or requests.Session()
        try:
            response = client.post(
                self.endpoint_url,
                json=payload,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise AnalysisApiError(f"Failed to POST analysis payload: {exc}") from exc

        try:
            return response.json()
        except ValueError:
            return {"status_code": response.status_code, "text": response.text}


def _format_timestamp(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
