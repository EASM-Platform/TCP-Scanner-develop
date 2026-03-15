from pathlib import Path

import pytest

from portscanner import NmapParseError, parse_nmap_xml

FIXTURE_PATH = Path(__file__).parent / "data" / "nmap_scan.xml"


def test_parse_nmap_xml_extracts_open_assets_for_host() -> None:
    results = parse_nmap_xml(FIXTURE_PATH)

    assert len(results) == 1
    assert results[0]["target_ip"] == "192.168.100.10"
    assert sorted(asset["port"] for asset in results[0]["assets"]) == [22, 80, 3306, 6379, 9000]


def test_http_banner_normalization_extracts_headers_and_title() -> None:
    http_asset = _asset_by_port(parse_nmap_xml(FIXTURE_PATH), 80)

    assert http_asset["service_name"] == "http"
    assert http_asset["version"] == "Apache httpd 2.4.62 Ubuntu"
    assert http_asset["banner_data"]["server_header"] == "Apache/2.4.62 (Ubuntu)"
    assert http_asset["banner_data"]["x_powered_by"] == "EASM Lab"
    assert http_asset["banner_data"]["title"] == "Welcome to Apache"
    assert "Apache/2.4.62 (Ubuntu)" in http_asset["banner_data"]["raw_banner"]


def test_mysql_banner_normalization_extracts_protocol_and_error() -> None:
    mysql_asset = _asset_by_port(parse_nmap_xml(FIXTURE_PATH), 3306)

    assert mysql_asset["service_name"] == "mysql"
    assert mysql_asset["banner_data"]["protocol_version"] == "10"
    assert mysql_asset["banner_data"]["extracted_version"] == "5.7.35"
    assert mysql_asset["banner_data"]["error_message"] == "Host is not allowed to connect from 192.168.100.99"


def test_ssh_banner_normalization_extracts_exact_banner() -> None:
    ssh_asset = _asset_by_port(parse_nmap_xml(FIXTURE_PATH), 22)

    assert ssh_asset["service_name"] == "ssh"
    assert ssh_asset["banner_data"]["ssh_banner"] == "SSH-2.0-OpenSSH_8.2p1"
    assert "Ubuntu-4ubuntu0.5" in ssh_asset["banner_data"]["raw_banner"]


def test_redis_banner_normalization_extracts_version_and_os() -> None:
    redis_asset = _asset_by_port(parse_nmap_xml(FIXTURE_PATH), 6379)

    assert redis_asset["service_name"] == "redis"
    assert redis_asset["banner_data"]["redis_version"] == "6.0.16"
    assert redis_asset["banner_data"]["os"] == "Linux 5.15.0 x86_64"


def test_unknown_service_preserves_raw_banner() -> None:
    unknown_asset = _asset_by_port(parse_nmap_xml(FIXTURE_PATH), 9000)

    assert unknown_asset["service_name"] == "unknown"
    assert unknown_asset["banner_data"]["raw_banner"] == (
        "Custom Gateway\n1.2.3\nopaque handshake token and full custom banner text"
    )


def test_parse_nmap_xml_raises_for_missing_file() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml("tests/data/does-not-exist.xml")


def _asset_by_port(results: list[dict], port: int) -> dict:
    for asset in results[0]["assets"]:
        if asset["port"] == port:
            return asset
    raise AssertionError(f"Port {port} was not found in parsed assets")
