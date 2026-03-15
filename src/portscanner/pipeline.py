from __future__ import annotations

import logging
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analysis_api import AnalysisApiClient, build_analysis_payload
from .banner_parser import parse_nmap_xml
from .naabu_wrapper import NaabuRunner
from .nmap_scanner import NmapBatchError, NmapScanner
from .shadow_it import TelegramNotifier, detect_new_assets, expand_target_cidrs, load_assets_state, save_assets_state
from .tcp_connect_scanner import TCPConnectScanner

LOGGER = logging.getLogger(__name__)


def run_scan_pipeline(
    *,
    target_cidr_path: str | Path,
    state_path: str | Path,
    nmap_output_dir: str | Path,
    naabu_runner: NaabuRunner | TCPConnectScanner | None = None,
    nmap_scanner: NmapScanner | None = None,
    telegram_notifier: TelegramNotifier | None = None,
    analysis_client: AnalysisApiClient | None = None,
) -> list[dict[str, Any]]:
    hosts = expand_target_cidrs(target_cidr_path)
    if not hosts:
        LOGGER.warning("No targets were expanded from %s", target_cidr_path)
        return []

    previous_state = load_assets_state(state_path)
    naabu_runner = naabu_runner or _default_scanner()

    current_state = naabu_runner.scan(hosts)
    new_events = detect_new_assets(current_state, previous_state)
    if telegram_notifier and new_events:
        try:
            telegram_notifier.send_events(new_events)
        except Exception:
            LOGGER.exception("Telegram notification failed; continuing with scan results")

    if not current_state:
        save_assets_state(state_path, current_state)
        return []

    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc)
    new_asset_keys = {(event.ip, event.port) for event in new_events}

    payloads: list[dict[str, Any]] = []
    try:
        xml_reports = _run_nmap_if_available(current_state, nmap_output_dir, nmap_scanner)
        if xml_reports:
            for report_path in xml_reports.values():
                parsed_hosts = parse_nmap_xml(report_path)
                for host_result in parsed_hosts:
                    payload = build_analysis_payload(
                        scan_id=scan_id,
                        timestamp=timestamp,
                        target_ip=host_result["target_ip"],
                        assets=host_result["assets"],
                        new_assets=new_asset_keys,
                    )
                    _post_payload_if_configured(analysis_client, payload)
                    payloads.append(payload)
        else:
            for target_ip, ports in current_state.items():
                payload = build_analysis_payload(
                    scan_id=scan_id,
                    timestamp=timestamp,
                    target_ip=target_ip,
                    assets=[
                        {
                            "port": port,
                            "protocol": "tcp",
                            "service_name": "unknown",
                            "version": None,
                            "banner_data": {"raw_banner": ""},
                        }
                        for port in ports
                    ],
                    new_assets=new_asset_keys,
                )
                _post_payload_if_configured(analysis_client, payload)
                payloads.append(payload)
    finally:
        save_assets_state(state_path, current_state)

    return payloads


def _default_scanner() -> NaabuRunner | TCPConnectScanner:
    if shutil.which("naabu"):
        return NaabuRunner()
    LOGGER.warning("naabu was not found on PATH; using built-in TCP connect scanner instead")
    return TCPConnectScanner()


def _run_nmap_if_available(
    current_state: dict[str, list[int]],
    nmap_output_dir: str | Path,
    nmap_scanner: NmapScanner | None,
) -> dict[str, Path]:
    if nmap_scanner is None:
        if not shutil.which("nmap"):
            LOGGER.warning("nmap was not found on PATH; returning port-only results")
            return {}
        nmap_scanner = NmapScanner(output_dir=nmap_output_dir)

    try:
        return nmap_scanner.scan_many(current_state)
    except NmapBatchError as exc:
        LOGGER.error("Continuing with %d successful nmap report(s)", len(exc.completed))
        if not exc.completed:
            return {}
        return exc.completed


def _post_payload_if_configured(
    analysis_client: AnalysisApiClient | None,
    payload: dict[str, Any],
) -> None:
    if analysis_client is None:
        return
    try:
        analysis_client.post_payload(payload)
    except Exception:
        LOGGER.exception("Analysis API delivery failed; continuing")
