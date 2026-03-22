import nmap


def create_nmap_scanner():
    scanner = nmap.PortScanner()
    return scanner


def run_nmap_scan(ip, open_ports):
    scanner = create_nmap_scanner()

    if not open_ports:
        return []

    port_string = ",".join(str(port) for port in open_ports)

    scanner.scan(ip, port_string, arguments="-sV")

    return scanner


def parse_nmap_results(scanner, ip):
    results = []

    if ip not in scanner.all_hosts():
        return results

    tcp_data = scanner[ip].get("tcp", {})

    for port, port_info in tcp_data.items():
        results.append({
            "port": port,
            "state": port_info.get("state", "unknown"),
            "service": port_info.get("name", "unknown"),
            "product": port_info.get("product", ""),
            "version": port_info.get("version", ""),
            "extra_info": port_info.get("extrainfo", "")
        })

    return results


if __name__ == "__main__":
    target_ip = "127.0.0.1"
    open_ports = [22, 80]

    scanner = run_nmap_scan(target_ip, open_ports)

    if not scanner:
        print("열린 포트가 없어서 Nmap 분석을 진행하지 않습니다.")
    else:
        results = parse_nmap_results(scanner, target_ip)

        print(f"Nmap 분석 대상: {target_ip}")
        for result in results:
            print(result)