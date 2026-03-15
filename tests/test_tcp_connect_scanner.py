import socket
import socketserver
import threading

import pytest

from portscanner.tcp_connect_scanner import TCPConnectScanError, TCPConnectScanner, parse_port_spec


class _SilentHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.recv(1)


def test_parse_port_spec_supports_ranges_and_values() -> None:
    assert parse_port_spec("22,80,1000-1002") == [22, 80, 1000, 1001, 1002]


def test_parse_port_spec_rejects_invalid_ranges() -> None:
    with pytest.raises(TCPConnectScanError):
        parse_port_spec("200-100")


def test_tcp_connect_scanner_detects_listening_port() -> None:
    server = socketserver.TCPServer(("127.0.0.1", 0), _SilentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        open_port = server.server_address[1]
        closed_port = _find_closed_port()

        scanner = TCPConnectScanner(
            port_spec=f"{closed_port},{open_port}",
            connect_timeout=0.2,
            concurrency=8,
        )
        results = scanner.scan(["127.0.0.1"])

        assert results == {"127.0.0.1": [open_port]}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _find_closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return port
