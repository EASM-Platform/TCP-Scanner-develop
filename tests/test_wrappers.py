import subprocess
from pathlib import Path

import portscanner.naabu_wrapper as naabu_wrapper
import portscanner.nmap_scanner as nmap_scanner


def test_naabu_runner_parses_json_lines(monkeypatch) -> None:
    calls = []

    def fake_run(command, capture_output, text, timeout, check):
        calls.append((command, timeout))
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout='{"ip":"192.168.100.10","port":80}\n{"host":"192.168.100.10","port":443}\n',
            stderr="",
        )

    monkeypatch.setattr(naabu_wrapper.subprocess, "run", fake_run)

    runner = naabu_wrapper.NaabuRunner(timeout_seconds=12)
    results = runner.scan(["192.168.100.10"])

    assert results == {"192.168.100.10": [80, 443]}
    assert calls[0][0][:4] == ["naabu", "-host", "192.168.100.10", "-p"]
    assert calls[0][1] == 12


def test_nmap_scanner_creates_expected_xml_output_path(tmp_path: Path, monkeypatch) -> None:
    def fake_run(command, capture_output, text, timeout, check):
        output_path = Path(command[command.index("-oX") + 1])
        output_path.write_text(
            "<?xml version='1.0'?><nmaprun><host><address addr='192.168.100.10' addrtype='ipv4' /></host></nmaprun>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(nmap_scanner.subprocess, "run", fake_run)

    scanner = nmap_scanner.NmapScanner(output_dir=tmp_path)
    reports = scanner.scan_many({"192.168.100.10": [443, 80]})

    assert list(reports) == ["192.168.100.10"]
    assert reports["192.168.100.10"].name == "192.168.100.10.xml"
    assert reports["192.168.100.10"].exists()
