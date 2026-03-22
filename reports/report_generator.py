import os
import json


def summarize_results(analyzed_results):
    summary = {
        "total": len(analyzed_results),
        "위험": 0,
        "주의": 0,
        "일반": 0,
        "알 수 없음": 0
    }

    for result in analyzed_results:
        risk_level = result.get("risk_level", "알 수 없음")

        if risk_level in summary:
            summary[risk_level] += 1
        else:
            summary["알 수 없음"] += 1

    return summary


def save_json_report(target_ip, analyzed_results, output_path="output/report.json", capture_results=None):
    summary = summarize_results(analyzed_results)

    if capture_results is None:
        capture_results = []

    report_data = {
        "target_ip": target_ip,
        "summary": summary,
        "results": analyzed_results,
        "captures": capture_results
    }

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4, ensure_ascii=False)

    return output_path


def save_html_report(target_ip, analyzed_results, output_path="output/report.html", capture_results=None):
    summary = summarize_results(analyzed_results)

    if capture_results is None:
        capture_results = []

    html_content = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Port Scan Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 30px;
            }}
            h1, h2 {{
                color: #333;
            }}
            .summary-box {{
                background-color: #f9f9f9;
                border: 1px solid #ddd;
                padding: 15px;
                margin-bottom: 20px;
                border-radius: 8px;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-top: 20px;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 10px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            .위험 {{
                color: red;
                font-weight: bold;
            }}
            .주의 {{
                color: orange;
                font-weight: bold;
            }}
            .일반 {{
                color: green;
                font-weight: bold;
            }}
            .capture-section {{
                margin-top: 40px;
            }}
            .capture-card {{
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 20px;
                background-color: #fafafa;
            }}
            .capture-card img {{
                max-width: 100%;
                border: 1px solid #ccc;
                margin-top: 10px;
            }}
        </style>
    </head>
    <body>
        <h1>서비스 포트 스캔 리포트</h1>

        <div class="summary-box">
            <p><strong>대상 IP:</strong> {target_ip}</p>
            <p><strong>총 결과 수:</strong> {summary['total']}</p>
            <p><strong>위험:</strong> {summary['위험']}</p>
            <p><strong>주의:</strong> {summary['주의']}</p>
            <p><strong>일반:</strong> {summary['일반']}</p>
            <p><strong>알 수 없음:</strong> {summary['알 수 없음']}</p>
        </div>

        <table>
            <tr>
                <th>포트</th>
                <th>상태</th>
                <th>서비스</th>
                <th>제품</th>
                <th>버전</th>
                <th>위험도</th>
                <th>이유</th>
            </tr>
    """

    for result in analyzed_results:
        html_content += f"""
            <tr>
                <td>{result['port']}</td>
                <td>{result['state']}</td>
                <td>{result['service']}</td>
                <td>{result['product']}</td>
                <td>{result['version']}</td>
                <td class="{result['risk_level']}">{result['risk_level']}</td>
                <td>{result['reason']}</td>
            </tr>
        """

    html_content += """
        </table>
    """

    html_content += """
        <div class="capture-section">
            <h2>웹 포트 자동 캡처 결과</h2>
    """

    if not capture_results:
        html_content += """
            <p>캡처된 웹 서비스가 없습니다.</p>
        """
    else:
        for capture in capture_results:
            screenshot_path = capture.get("screenshot_path")

            html_content += f"""
            <div class="capture-card">
                <p><strong>포트:</strong> {capture.get('port')}</p>
                <p><strong>서비스:</strong> {capture.get('service')}</p>
                <p><strong>캡처 파일:</strong> {screenshot_path}</p>
            """

            if screenshot_path:
                image_filename = os.path.basename(screenshot_path)
                html_content += f"""
                <img src="{image_filename}" alt="capture_{capture.get('port')}">
                """
            else:
                html_content += """
                <p>캡처 실패 또는 파일이 없습니다.</p>
                """

            html_content += """
            </div>
            """

    html_content += """
        </div>
    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(html_content)

    return output_path


if __name__ == "__main__":
    sample_results = [
        {
            "port": 22,
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1",
            "extra_info": "Ubuntu",
            "risk_level": "일반",
            "reason": "일반적인 원격 관리 서비스입니다."
        },
        {
            "port": 23,
            "state": "open",
            "service": "telnet",
            "product": "",
            "version": "",
            "extra_info": "",
            "risk_level": "위험",
            "reason": "평문 통신을 사용하여 정보 노출 위험이 있습니다."
        }
    ]

    saved_path = save_json_report("127.0.0.1", sample_results)
    print(f"JSON 리포트 저장 완료: {saved_path}")

    html_path = save_html_report("127.0.0.1", sample_results)
    print(f"HTML 리포트 저장 완료: {html_path}")