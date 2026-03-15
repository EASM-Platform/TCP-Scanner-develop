from pathlib import Path

from portscanner.shadow_it import TelegramNotifier, detect_new_assets, expand_target_cidrs, load_assets_state, save_assets_state


def test_expand_target_cidrs_reads_comments_and_deduplicates_hosts(tmp_path: Path) -> None:
    target_file = tmp_path / "target_cidr.txt"
    target_file.write_text(
        "# demo\n192.168.100.0/30\n192.168.100.2/32\n",
        encoding="utf-8",
    )

    assert expand_target_cidrs(target_file) == ["192.168.100.1", "192.168.100.2"]


def test_asset_state_round_trip_and_new_asset_detection(tmp_path: Path) -> None:
    state_file = tmp_path / "assets_state.json"
    save_assets_state(
        state_file,
        {
            "192.168.100.2": [443],
            "192.168.100.1": [22, 80],
        },
    )

    loaded = load_assets_state(state_file)
    assert loaded == {
        "192.168.100.1": {22, 80},
        "192.168.100.2": {443},
    }

    events = detect_new_assets(
        current_results={"192.168.100.1": [22, 80, 443], "192.168.100.3": [8080]},
        previous_state=loaded,
    )
    assert [(event.ip, event.port) for event in events] == [
        ("192.168.100.1", 443),
        ("192.168.100.3", 8080),
    ]


def test_telegram_notifier_posts_expected_message() -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, bool]:
            return {"ok": True}

    class FakeSession:
        def __init__(self) -> None:
            self.calls = []

        def post(self, url: str, json: dict, timeout: float) -> FakeResponse:
            self.calls.append((url, json, timeout))
            return FakeResponse()

    session = FakeSession()
    notifier = TelegramNotifier(bot_token="token", chat_id="chat", session=session)
    notifier.send_events(detect_new_assets({"192.168.100.10": [80]}, {}))

    assert session.calls[0][0] == "https://api.telegram.org/bottoken/sendMessage"
    assert session.calls[0][1]["chat_id"] == "chat"
    assert session.calls[0][1]["text"] == "[신규 자산 발견] IP: 192.168.100.10, Port: 80 가 새로 활성화되었습니다."
