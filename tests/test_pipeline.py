from pathlib import Path

from portscanner.analysis_api import AnalysisApiError
from portscanner.pipeline import run_scan_pipeline

FIXTURE_PATH = Path(__file__).parent / "data" / "nmap_scan.xml"


class FakeNaabuRunner:
    def scan(self, hosts: list[str]) -> dict[str, list[int]]:
        assert hosts == ["192.168.100.10"]
        return {"192.168.100.10": [22, 80, 3306, 6379, 9000]}


class FakeNmapScanner:
    def __init__(self) -> None:
        self.received_targets: dict[str, list[int]] | None = None

    def scan_many(self, targets: dict[str, list[int]]) -> dict[str, Path]:
        self.received_targets = targets
        return {"192.168.100.10": FIXTURE_PATH}


class FakeTelegramNotifier:
    def __init__(self) -> None:
        self.events = []

    def send_events(self, events) -> None:
        self.events = list(events)


class FakeAnalysisClient:
    def __init__(self) -> None:
        self.payloads = []

    def post_payload(self, payload: dict) -> dict[str, str]:
        self.payloads.append(payload)
        return {"status": "received"}


class FailingTelegramNotifier:
    def send_events(self, events) -> None:
        raise RuntimeError("telegram down")


class FailingAnalysisClient:
    def __init__(self) -> None:
        self.payloads = []

    def post_payload(self, payload: dict) -> dict[str, str]:
        self.payloads.append(payload)
        raise AnalysisApiError("api down")


def test_run_scan_pipeline_builds_payloads_and_updates_state(tmp_path: Path) -> None:
    target_file = tmp_path / "target_cidr.txt"
    target_file.write_text("192.168.100.10/32\n", encoding="utf-8")

    state_file = tmp_path / "assets_state.json"
    state_file.write_text('{"192.168.100.10":[22]}', encoding="utf-8")

    fake_nmap = FakeNmapScanner()
    fake_notifier = FakeTelegramNotifier()
    fake_api = FakeAnalysisClient()

    payloads = run_scan_pipeline(
        target_cidr_path=target_file,
        state_path=state_file,
        nmap_output_dir=tmp_path / "nmap",
        naabu_runner=FakeNaabuRunner(),
        nmap_scanner=fake_nmap,
        telegram_notifier=fake_notifier,
        analysis_client=fake_api,
    )

    assert len(payloads) == 1
    assert fake_nmap.received_targets == {"192.168.100.10": [22, 80, 3306, 6379, 9000]}
    assert [(event.ip, event.port) for event in fake_notifier.events] == [
        ("192.168.100.10", 80),
        ("192.168.100.10", 3306),
        ("192.168.100.10", 6379),
        ("192.168.100.10", 9000),
    ]
    assert len(fake_api.payloads) == 1
    assert state_file.read_text(encoding="utf-8").strip() == (
        '{\n  "192.168.100.10": [\n    22,\n    80,\n    3306,\n    6379,\n    9000\n  ]\n}'
    )

    assets_by_port = {asset["port"]: asset for asset in payloads[0]["assets"]}
    assert assets_by_port[22]["is_new"] is False
    assert assets_by_port[80]["is_new"] is True


def test_run_scan_pipeline_persists_state_when_notifications_and_api_fail(tmp_path: Path) -> None:
    target_file = tmp_path / "target_cidr.txt"
    target_file.write_text("192.168.100.10/32\n", encoding="utf-8")

    state_file = tmp_path / "assets_state.json"
    fake_api = FailingAnalysisClient()

    payloads = run_scan_pipeline(
        target_cidr_path=target_file,
        state_path=state_file,
        nmap_output_dir=tmp_path / "nmap",
        naabu_runner=FakeNaabuRunner(),
        nmap_scanner=FakeNmapScanner(),
        telegram_notifier=FailingTelegramNotifier(),
        analysis_client=fake_api,
    )

    assert len(payloads) == 1
    assert len(fake_api.payloads) == 1
    assert '"192.168.100.10"' in state_file.read_text(encoding="utf-8")
