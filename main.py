from scanner.port_scanner import scan_ports, get_open_ports
from scanner.nmap_scanner import run_nmap_scan, parse_nmap_results
from analyzer.risk_analyzer import analyze_nmap_results
from reports.report_generator import save_json_report, save_html_report
from resolver import resolve_target
from visualizer.web_capture import capture_from_results

COMMON_PORTS = [22, 80, 111, 139, 445, 2042, 8000]


def parse_targets(target_input):
    raw_targets = target_input.split(",")
    clean_targets = []

    for target in raw_targets:
        target = target.strip()
        if target:
            clean_targets.append(target)

    return clean_targets


def make_safe_filename(name):
    return name.replace(".", "_").replace(":", "_").replace("/", "_")


def main():
    target_input = input("스캔할 IP, 도메인 또는 CIDR을 입력하세요(여러 개는 쉼표로 구분): ").strip()

    if not target_input:
        print("입력값이 필요합니다.")
        return

    target_list = parse_targets(target_input)

    if not target_list:
        print("유효한 입력값이 없습니다.")
        return

    for single_target in target_list:
        print("\n" + "=" * 60)
        print(f"입력값 처리 중: {single_target}")

        resolved_target = resolve_target(single_target)

        if not resolved_target:
            print("올바른 IP, 도메인 또는 CIDR이 아닙니다. 건너뜁니다.")
            continue

        print(f"입력 대상: {resolved_target['original_target']}")
        print(f"대상 유형: {resolved_target['target_type']}")

        if resolved_target["target_type"] == "cidr":
            scan_ip_list = resolved_target["resolved_ips"]
            print(f"확장된 IP 개수: {len(scan_ip_list)}")
            print(f"확장된 IP 목록: {scan_ip_list}")
        else:
            scan_ip_list = [resolved_target["resolved_ip"]]

        for target_ip in scan_ip_list:
            print("\n" + "-" * 40)
            print(f"실제 스캔 IP: {target_ip}")

            results = scan_ports(target_ip, COMMON_PORTS)

            print("\n[기본 포트 스캔 결과]")
            for result in results:
                print(f"포트 {result['port']}: {result['status']}")

            open_ports = get_open_ports(results)
            print(f"\n열린 포트 목록: {open_ports}")

            if not open_ports:
                print("\n열린 포트가 없어 Nmap 분석을 진행하지 않습니다.")
                continue

            scanner = run_nmap_scan(target_ip, open_ports)
            nmap_results = parse_nmap_results(scanner, target_ip)
            analyzed_results = analyze_nmap_results(nmap_results)
            capture_results = capture_from_results(target_ip, analyzed_results)

            print("\n[서비스 위험도 분석 결과]")
            for result in analyzed_results:
                print(
                    f"포트 {result['port']} | "
                    f"상태: {result['state']} | "
                    f"서비스: {result['service']} | "
                    f"제품: {result['product']} | "
                    f"버전: {result['version']} | "
                    f"위험도: {result['risk_level']} | "
                    f"이유: {result['reason']}"
                )

            print("\n[웹 캡처 결과]")
            if not capture_results:
                print("캡처된 웹 서비스가 없습니다.")
            else:
                for capture in capture_results:
                    print(
                        f"포트 {capture['port']} | "
                        f"서비스: {capture['service']} | "
                        f"캡처 파일: {capture['screenshot_path']}"
                    )

            safe_name = make_safe_filename(f"{resolved_target['original_target']}_{target_ip}")
            json_output_path = f"output/report_{safe_name}.json"
            html_output_path = f"output/report_{safe_name}.html"

            json_report_path = save_json_report(
                target_ip,
                analyzed_results,
                json_output_path,
                capture_results
            )
            html_report_path = save_html_report(
                target_ip,
                analyzed_results,
                html_output_path,
                capture_results
            )

            print(f"\nJSON 리포트 저장 완료: {json_report_path}")
            print(f"HTML 리포트 저장 완료: {html_report_path}")


if __name__ == "__main__":
    main()