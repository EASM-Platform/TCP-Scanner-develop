import socket
import ipaddress


def is_valid_ip(value):
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False


def is_valid_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def expand_cidr_to_ips(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
        return ip_list
    except ValueError:
        return []


def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None


def resolve_target(target):
    if is_valid_ip(target):
        return {
            "original_target": target,
            "resolved_ip": target,
            "target_type": "ip"
        }

    if is_valid_cidr(target):
        expanded_ips = expand_cidr_to_ips(target)
        return {
            "original_target": target,
            "resolved_ips": expanded_ips,
            "target_type": "cidr"
        }

    resolved_ip = resolve_domain_to_ip(target)
    if resolved_ip:
        return {
            "original_target": target,
            "resolved_ip": resolved_ip,
            "target_type": "domain"
        }

    return None


if __name__ == "__main__":
    test_targets = [
        "192.168.227.128",
        "localhost",
        "192.168.227.0/30",
        "invalid_target"
    ]

    for target in test_targets:
        result = resolve_target(target)
        print(f"입력값: {target} -> 결과: {result}")