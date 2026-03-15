from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

SSH_BANNER_RE = re.compile(r"(SSH-\d\.\d-[^\s]+)")
MYSQL_PROTOCOL_RE = re.compile(r"protocol(?:\s+version)?[:=]?\s*(\d+)", re.IGNORECASE)
MYSQL_ERROR_RE = re.compile(
    r"(Host is not allowed to connect[^\r\n]*|Access denied[^\r\n]*|Too many connections[^\r\n]*)",
    re.IGNORECASE,
)
SEMVER_RE = re.compile(r"\b(\d+\.\d+\.\d+(?:[-._][A-Za-z0-9]+)*)\b")
REDIS_VERSION_RE = re.compile(r"redis_version\s*[:=]\s*([^\r\n]+)", re.IGNORECASE)
REDIS_OS_RE = re.compile(r"os\s*[:=]\s*([^\r\n]+)", re.IGNORECASE)


class NmapParseError(RuntimeError):
    """Raised when an Nmap XML file cannot be parsed."""


def parse_nmap_xml(xml_path: str | Path) -> list[dict[str, Any]]:
    """Parse an Nmap XML file and return normalized assets grouped by host."""

    path = Path(xml_path)
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise NmapParseError(f"Failed to parse Nmap XML: {path}") from exc

    results: list[dict[str, Any]] = []
    for host in root.findall("host"):
        target_ip = _extract_target_ip(host)
        if not target_ip:
            LOGGER.warning("Skipping host without an address in %s", path)
            continue

        assets: list[dict[str, Any]] = []
        for port_node in host.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue

            port_text = port_node.get("portid")
            if not port_text or not port_text.isdigit():
                LOGGER.warning("Skipping port without numeric portid for host %s", target_ip)
                continue

            asset = _normalize_port(
                port=int(port_text),
                protocol=port_node.get("protocol", "tcp"),
                service_node=port_node.find("service"),
                scripts=port_node.findall("script"),
            )
            assets.append(asset)

        results.append({"target_ip": target_ip, "assets": assets})

    return results


def _normalize_port(
    *,
    port: int,
    protocol: str,
    service_node: ET.Element | None,
    scripts: list[ET.Element],
) -> dict[str, Any]:
    service_name = _canonical_service_name(service_node)
    service_version = _compose_service_version(service_node)
    raw_banner = _compose_raw_banner(service_node, scripts)

    banner_data: dict[str, Any] = {"raw_banner": raw_banner}
    if service_name in {"http", "https"}:
        banner_data.update(_parse_http_banner(scripts, raw_banner))
    elif service_name == "mysql":
        banner_data.update(_parse_mysql_banner(service_version, raw_banner))
    elif service_name == "ssh":
        banner_data.update(_parse_ssh_banner(raw_banner))
    elif service_name == "redis":
        banner_data.update(_parse_redis_banner(scripts, raw_banner))

    return {
        "port": port,
        "protocol": protocol,
        "service_name": service_name,
        "version": service_version,
        "banner_data": banner_data,
    }


def _extract_target_ip(host: ET.Element) -> str | None:
    for address in host.findall("address"):
        if address.get("addrtype") in {"ipv4", "ipv6"}:
            return address.get("addr")
    return None


def _canonical_service_name(service_node: ET.Element | None) -> str:
    if service_node is None:
        return "unknown"

    name = (service_node.get("name") or "unknown").lower()
    tunnel = (service_node.get("tunnel") or "").lower()
    if tunnel == "ssl" and "http" in name:
        return "https"
    if name.startswith("https"):
        return "https"
    if "http" in name:
        return "http"
    return name


def _compose_service_version(service_node: ET.Element | None) -> str | None:
    if service_node is None:
        return None

    parts = [
        service_node.get("product"),
        service_node.get("version"),
        service_node.get("extrainfo"),
    ]
    value = " ".join(part.strip() for part in parts if part and part.strip())
    return value or None


def _compose_raw_banner(service_node: ET.Element | None, scripts: list[ET.Element]) -> str:
    fragments: list[str] = []

    if service_node is not None:
        for key in ("banner", "product", "version", "extrainfo", "hostname", "ostype"):
            value = service_node.get(key)
            if value and value.strip():
                fragments.append(value.strip())

    for script in scripts:
        flattened = _flatten_script(script)
        if flattened:
            fragments.append(flattened)

    return "\n".join(_dedupe_preserve_order(fragments))


def _flatten_script(script: ET.Element) -> str:
    fragments: list[str] = []

    output = script.get("output")
    if output and output.strip():
        fragments.append(output.strip())

    for node in script.iter():
        if node is script:
            continue
        text = (node.text or "").strip()
        if not text:
            continue

        key = node.get("key")
        if key:
            fragments.append(f"{key}:{text}")
        else:
            fragments.append(text)

    return "\n".join(_dedupe_preserve_order(fragments))


def _parse_http_banner(scripts: list[ET.Element], raw_banner: str) -> dict[str, Any]:
    script_outputs = _script_outputs_by_id(scripts)
    headers_text = script_outputs.get("http-headers", raw_banner)
    server_header = (
        _clean_script_output(script_outputs.get("http-server-header"))
        or _extract_http_header(headers_text, "Server")
    )
    title = _clean_script_output(script_outputs.get("http-title"))
    x_powered_by = _extract_http_header(headers_text, "X-Powered-By")

    return {
        "server_header": server_header,
        "x_powered_by": x_powered_by,
        "title": title,
    }


def _parse_mysql_banner(service_version: str | None, raw_banner: str) -> dict[str, Any]:
    protocol_match = MYSQL_PROTOCOL_RE.search(raw_banner)
    error_match = MYSQL_ERROR_RE.search(raw_banner)
    version_match = SEMVER_RE.search(service_version or "") or SEMVER_RE.search(raw_banner)

    return {
        "protocol_version": protocol_match.group(1) if protocol_match else None,
        "error_message": error_match.group(1).strip() if error_match else None,
        "extracted_version": version_match.group(1) if version_match else None,
    }


def _parse_ssh_banner(raw_banner: str) -> dict[str, Any]:
    banner_match = SSH_BANNER_RE.search(raw_banner)
    return {"ssh_banner": banner_match.group(1) if banner_match else None}


def _parse_redis_banner(scripts: list[ET.Element], raw_banner: str) -> dict[str, Any]:
    script_outputs = _script_outputs_by_id(scripts)
    redis_info = script_outputs.get("redis-info", raw_banner)
    version_match = REDIS_VERSION_RE.search(redis_info)
    os_match = REDIS_OS_RE.search(redis_info)

    return {
        "redis_version": version_match.group(1).strip() if version_match else None,
        "os": os_match.group(1).strip() if os_match else None,
    }


def _script_outputs_by_id(scripts: list[ET.Element]) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for script in scripts:
        script_id = script.get("id")
        if not script_id:
            continue
        outputs[script_id] = _flatten_script(script)
    return outputs


def _extract_http_header(headers_text: str | None, header_name: str) -> str | None:
    if not headers_text:
        return None

    for line in headers_text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() == header_name.lower():
            candidate = value.strip()
            return candidate or None
    return None


def _clean_script_output(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
