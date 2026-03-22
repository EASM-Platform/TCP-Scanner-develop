import socket


def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return "open"
        else:
            return "closed"

    except Exception as e:
        print(f"오류 발생 - IP: {ip}, 포트: {port}, 오류: {e}")
        return "error"


def scan_ports(ip, ports):
    results = []

    for port in ports:
        status = scan_port(ip, port)
        results.append({
            "port": port,
            "status": status
        })

    return results


def get_open_ports(results):
    open_ports = []

    for result in results:
        if result["status"] == "open":
            open_ports.append(result["port"])

    return open_ports


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    test_ports = [22, 80, 443, 3306]

    results = scan_ports(target_ip, test_ports)

    print(f"스캔 대상: {target_ip}")
    for result in results:
        print(f"포트 {result['port']}: {result['status']}")

    open_ports = get_open_ports(results)
    print(f"열린 포트 목록: {open_ports}")