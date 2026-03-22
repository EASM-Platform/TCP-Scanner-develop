RISK_RULES = {
    "telnet": {
        "risk_level": "위험",
        "reason": "평문 통신을 사용하여 정보 노출 위험이 있습니다."
    },
    "ftp": {
        "risk_level": "위험",
        "reason": "평문 인증을 사용할 수 있어 계정 정보 노출 위험이 있습니다."
    },
    "mysql": {
        "risk_level": "주의",
        "reason": "DB 포트가 외부에 노출되면 보안상 주의가 필요합니다."
    },
    "ms-sql-s": {
        "risk_level": "주의",
        "reason": "데이터베이스 서비스가 외부에 노출되면 보안상 주의가 필요합니다."
    },
    "microsoft-ds": {
        "risk_level": "주의",
        "reason": "SMB 서비스는 외부 노출 시 공격 표면이 커질 수 있습니다."
    },
    "netbios-ssn": {
        "risk_level": "주의",
        "reason": "NetBIOS 서비스는 외부 노출 시 주의가 필요합니다."
    },
    "rdp": {
        "risk_level": "주의",
        "reason": "원격 데스크톱 서비스는 공격 대상이 될 수 있습니다."
    },
    "ms-wbt-server": {
        "risk_level": "주의",
        "reason": "원격 데스크톱 서비스는 공격 대상이 될 수 있습니다."
    },
    "rpcbind": {
        "risk_level": "주의",
        "reason": "RPC 서비스는 외부 노출 시 내부 서비스 정보 노출 가능성이 있어 주의가 필요합니다."
    },
    "http-alt": {
        "risk_level": "일반",
        "reason": "기본 포트 외에서 동작하는 웹 서비스입니다."
    },
    "tcpwrapped": {
        "risk_level": "알 수 없음",
        "reason": "서비스가 접근 제어나 래핑으로 보호되어 있어 정확한 식별이 어렵습니다."
    },
    "ssh": {
        "risk_level": "일반",
        "reason": "일반적인 원격 관리 서비스입니다."
    },
    "http": {
        "risk_level": "일반",
        "reason": "일반적인 웹 서비스입니다."
    },
    "https": {
        "risk_level": "일반",
        "reason": "암호화된 일반 웹 서비스입니다."
    }
}


def analyze_single_service(service_name):
    service_name = service_name.lower()

    if service_name in RISK_RULES:
        return RISK_RULES[service_name]
    else:
        return {
            "risk_level": "알 수 없음",
            "reason": "정의된 위험도 기준이 없는 서비스입니다."
        }


def analyze_nmap_results(nmap_results):
    analyzed_results = []

    for result in nmap_results:
        service_name = result.get("service", "unknown")
        risk_info = analyze_single_service(service_name)

        analyzed_result = {
            "port": result.get("port"),
            "state": result.get("state"),
            "service": service_name,
            "product": result.get("product", ""),
            "version": result.get("version", ""),
            "extra_info": result.get("extra_info", ""),
            "risk_level": risk_info["risk_level"],
            "reason": risk_info["reason"]
        }

        analyzed_results.append(analyzed_result)

    return analyzed_results


if __name__ == "__main__":
    sample_nmap_results = [
        {
            "port": 22,
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1",
            "extra_info": "Ubuntu"
        },
        {
            "port": 23,
            "state": "open",
            "service": "telnet",
            "product": "",
            "version": "",
            "extra_info": ""
        },
        {
            "port": 3306,
            "state": "open",
            "service": "mysql",
            "product": "MySQL",
            "version": "5.7",
            "extra_info": ""
        }
    ]

    analyzed_results = analyze_nmap_results(sample_nmap_results)

    for result in analyzed_results:
        print(result)