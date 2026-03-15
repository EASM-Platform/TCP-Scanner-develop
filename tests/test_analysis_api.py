from datetime import datetime, timezone

from portscanner.analysis_api import AnalysisApiClient, build_analysis_payload


def test_build_analysis_payload_marks_new_assets_and_formats_timestamp() -> None:
    payload = build_analysis_payload(
        scan_id="scan-123",
        timestamp=datetime(2026, 3, 15, 0, 1, 2, tzinfo=timezone.utc),
        target_ip="192.168.100.10",
        assets=[
            {
                "port": 80,
                "protocol": "tcp",
                "service_name": "http",
                "version": "Apache httpd 2.4.62",
                "banner_data": {"title": "Welcome"},
            }
        ],
        new_assets={("192.168.100.10", 80)},
    )

    assert payload["scan_id"] == "scan-123"
    assert payload["timestamp"] == "2026-03-15T00:01:02Z"
    assert payload["assets"][0]["is_new"] is True


def test_analysis_api_client_posts_json_payload() -> None:
    class FakeResponse:
        status_code = 200
        text = "ok"

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"status": "received"}

    class FakeSession:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict, float]] = []

        def post(self, url: str, json: dict, timeout: float) -> FakeResponse:
            self.calls.append((url, json, timeout))
            return FakeResponse()

    session = FakeSession()
    client = AnalysisApiClient("https://example.test/api/assets", session=session)
    response = client.post_payload({"scan_id": "scan-123"})

    assert response == {"status": "received"}
    assert session.calls[0][0] == "https://example.test/api/assets"
    assert session.calls[0][1] == {"scan_id": "scan-123"}
