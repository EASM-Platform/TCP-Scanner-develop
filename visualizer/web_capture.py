import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options


def is_web_service(service_name):
    web_services = ["http", "https", "http-alt"]
    return service_name.lower() in web_services


def build_url(ip, port, service_name):
    if service_name.lower() == "https":
        protocol = "https"
    else:
        protocol = "http"

    return f"{protocol}://{ip}:{port}"


def make_capture_filename(ip, port):
    safe_ip = ip.replace(".", "_")
    return f"output/capture_{safe_ip}_{port}.png"


def create_browser():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1280,1024")
    chrome_options.add_argument("--ignore-certificate-errors")

    driver = webdriver.Chrome(options=chrome_options)
    return driver


def capture_web_page(ip, port, service_name):
    if not is_web_service(service_name):
        return None

    url = build_url(ip, port, service_name)
    screenshot_path = make_capture_filename(ip, port)

    try:
        driver = create_browser()
        driver.get(url)
        time.sleep(2)
        driver.save_screenshot(screenshot_path)
        driver.quit()
        return screenshot_path

    except Exception as e:
        print(f"웹 캡처 실패 - URL: {url}, 오류: {e}")
        return None


def capture_from_results(ip, analyzed_results):
    capture_results = []

    for result in analyzed_results:
        service_name = result.get("service", "")
        port = result.get("port")

        if is_web_service(service_name):
            screenshot_path = capture_web_page(ip, port, service_name)
            capture_results.append({
                "port": port,
                "service": service_name,
                "screenshot_path": screenshot_path
            })

    return capture_results

if __name__ == "__main__":
    sample_ip = "192.168.227.128"
    sample_results = [
        {"port": 80, "service": "http"},
        {"port": 8000, "service": "http-alt"},
        {"port": 22, "service": "ssh"}
    ]

    capture_results = capture_from_results(sample_ip, sample_results)

    for capture in capture_results:
        print(capture)