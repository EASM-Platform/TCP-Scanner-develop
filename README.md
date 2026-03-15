# Portscanner

폐쇄망 테스트 랩에서 실제로 실행하고 검증할 수 있는 포트 스캐너 프로젝트입니다.  
핵심 목표는 "대상 호스트 또는 CIDR 대역을 입력받아 열린 포트를 찾고, 필요하면 서비스 식별과 배너 정규화까지 이어지는 실행 가능한 포트 스캔 파이프라인"을 제공하는 것입니다.

이 저장소는 EASM 전체 플랫폼을 염두에 두고 설계했지만, 현재 GitHub에 올리는 기준에서 가장 중요한 deliverable은 `포트 스캔`입니다. 따라서 CLI와 실제 랩 검증도 포트 스캔 중심으로 정리되어 있습니다.

## 1. 무엇을 할 수 있는가

- Docker 기반 폐쇄망 테스트 랩을 올릴 수 있습니다.
- 단일 호스트 또는 CIDR 파일을 대상으로 포트 스캔을 실행할 수 있습니다.
- `naabu`가 설치되어 있으면 `naabu`로, 없으면 내장 TCP connect 스캐너로 자동 fallback 됩니다.
- 스캔 결과를 `assets_state.json`에 저장하고, 이전 결과와 비교하여 신규 자산(IP/Port)을 판별할 수 있습니다.
- `nmap`이 설치되어 있으면 열린 포트에 대해 서비스/버전 식별을 추가로 수행할 수 있습니다.
- Nmap XML을 파싱하여 HTTP, MySQL, SSH, Redis 배너를 정규화할 수 있습니다.
- 위협 분석 파트로 넘길 JSON payload를 생성하는 라이브러리 코드가 포함되어 있습니다.

## 2. 현재 구현 범위

### 포트 스캔 핵심

- 실행 CLI
- TCP connect 기반 실제 포트 스캔
- `naabu` 래퍼
- `nmap` 래퍼
- 상태 파일 저장 및 신규 자산 비교
- Docker 테스트 랩

### 확장 모듈

- Telegram 알림 모듈
- 분석 API payload 생성/전송 모듈
- Nmap XML 배너 정규화 모듈

주의:
CLI는 현재 `포트 스캔`에 집중되어 있습니다.  
Telegram/API 전송 모듈은 라이브러리로 구현되어 있지만, CLI 옵션으로 노출하지는 않았습니다.

## 3. 핵심 아키텍처

```text
User / CLI
   |
   v
Target Resolution
  - --host
  - target_cidr.txt
   |
   v
Scan Orchestrator (run_scan_pipeline)
   |
   +--> Scan Backend
   |     - NaabuRunner
   |     - TCPConnectScanner
   |
   +--> State / Diff
   |     - load_assets_state
   |     - detect_new_assets
   |     - save_assets_state
   |
   +--> Optional Service Detection
   |     - NmapScanner
   |     - parse_nmap_xml
   |
   +--> Optional Integration
         - TelegramNotifier
         - AnalysisApiClient
```

핵심 설계 포인트는 다음과 같습니다.

- `CLI layer`는 사용자 입력을 정리하고, 스캔 백엔드와 출력 형식을 선택합니다.
- `Pipeline layer`는 전체 실행 흐름을 조율합니다.
- `Scan backend layer`는 실제 포트 오픈 여부를 판별합니다.
- `Enrichment layer`는 필요할 때만 `nmap`과 XML parser를 사용합니다.
- `State layer`는 이전 스캔 상태와 비교해 신규 자산을 찾습니다.
- `Integration layer`는 부가 기능이며, 실패하더라도 스캔 전체가 멈추지 않도록 설계했습니다.

## 4. 세부 구현 아키텍처

### 4.1 CLI 계층

파일:
- `portscanner.ps1`
- `portscanner.cmd`
- `portscanner_cli.py`
- `src/portscanner/cli.py`

역할:
- `scan`, `lab-up`, `lab-down` 세 가지 명령을 제공합니다.
- `--backend auto|naabu|tcp`로 백엔드를 선택합니다.
- `--ports`는 PowerShell에서 쉼표가 배열로 분해되는 문제를 고려해 `22,80,443` 또는 `22 80 443` 모두 받을 수 있게 구현했습니다.
- 결과는 표준 출력 JSON 또는 `--json-out` 파일로 저장할 수 있습니다.

설계 이유:
- Windows PowerShell, `cmd`, Python 직접 실행을 모두 지원하기 위해 설치형 console script에 의존하지 않고 래퍼 스크립트를 같이 넣었습니다.
- GitHub 사용자가 clone 후 바로 실행할 수 있도록 `.\portscanner.ps1` 경로를 기본 진입점으로 삼았습니다.

### 4.2 파이프라인 계층

파일:
- `src/portscanner/pipeline.py`

역할:
- 대상 목록 확장
- 스캔 백엔드 실행
- 상태 비교 및 신규 자산 탐지
- 선택적 `nmap` 실행
- 선택적 XML 파싱
- 상태 저장

중요한 동작:
- `naabu`가 없으면 자동으로 TCP connect backend로 fallback 됩니다.
- `nmap`이 없으면 포트 결과만 반환합니다.
- Telegram/API 전송 실패는 로그만 남기고 계속 진행합니다.
- `assets_state.json`은 `finally`에서 저장하여, 부가 기능 실패 때문에 상태 파일이 유실되지 않도록 했습니다.

### 4.3 포트 스캔 백엔드

#### A. Naabu backend

파일:
- `src/portscanner/naabu_wrapper.py`

역할:
- `naabu -host ... -p ... -c ... -rate ... -silent -json` 형식으로 실행합니다.
- JSON line 출력을 파싱해 `{ip: [ports...]}` 구조로 반환합니다.
- 긴 host list는 명령행 길이 제한을 피하기 위해 batch로 분할합니다.

사용 시점:
- 대규모 범위 스캔
- `naabu`가 설치된 환경

#### B. TCP connect backend

파일:
- `src/portscanner/tcp_connect_scanner.py`

역할:
- Python `socket.connect_ex()` 기반 스캐너입니다.
- 포트 큐를 만들고 worker thread가 병렬로 꺼내서 연결을 시도합니다.
- `1-65535`, `22,80,443`, `22 80 443` 같은 포트 표기를 모두 처리합니다.

사용 시점:
- `naabu`가 없는 환경
- 실제 로컬 테스트
- GitHub clone 직후 빠른 검증

제한:
- 대규모 CIDR에 대한 초고속 스캔은 `naabu`보다 불리합니다.
- 현재 구현은 포트 오픈 여부 확인에 최적화되어 있고, raw SYN scan 같은 저수준 스캔은 하지 않습니다.

### 4.4 Nmap 정밀 분석 계층

파일:
- `src/portscanner/nmap_scanner.py`

역할:
- 열린 포트만 대상으로 `nmap -sV -sC -Pn -T4 -p ... -oX ...`를 실행합니다.
- `ThreadPoolExecutor(max_workers=5)`로 여러 호스트를 병렬 처리합니다.
- 호스트별 XML 파일을 남깁니다.

실행 조건:
- CLI에서 `--skip-nmap`을 주지 않았고
- 시스템에 `nmap`이 설치되어 있어야 합니다.

### 4.5 배너 정규화 계층

파일:
- `src/portscanner/banner_parser.py`

지원 대상:
- HTTP / HTTPS
- MySQL
- SSH
- Redis

파싱 방식:
- XML의 `<service>`와 `<script>`를 함께 읽습니다.
- 스크립트 출력과 `elem`, `table` 내용을 flatten 한 뒤 서비스별 규칙을 적용합니다.
- 알 수 없는 서비스는 구조화된 필드를 강제로 만들지 않고 `raw_banner`를 보존합니다.

핵심 필드 예시:
- HTTP: `server_header`, `x_powered_by`, `title`
- MySQL: `protocol_version`, `error_message`, `extracted_version`
- SSH: `ssh_banner`
- Redis: `redis_version`, `os`

### 4.6 상태 관리 / 신규 자산 탐지

파일:
- `src/portscanner/shadow_it.py`

역할:
- `target_cidr.txt` 파일 읽기
- CIDR 확장
- `assets_state.json` 로드/저장
- 현재 결과와 이전 결과 비교
- 신규 `(IP, Port)` 탐지

구현 포인트:
- JSON state 저장은 `.tmp` 파일에 먼저 쓰고 교체하는 atomic replace 방식입니다.
- 이전 결과가 없으면 첫 실행 결과 전체가 `new_assets`가 됩니다.
- 동일 상태로 다시 실행하면 `new_assets`는 빈 배열이 됩니다.

### 4.7 분석 API / Telegram 계층

파일:
- `src/portscanner/analysis_api.py`
- `src/portscanner/shadow_it.py`

현재 위치:
- CLI의 1차 목적은 포트 스캔이므로 이 계층은 라이브러리 확장 기능으로 남겨두었습니다.

의도:
- 이후 EASM 플랫폼 전체 연결 시 재사용할 수 있도록 미리 구현되어 있습니다.

## 5. 작동 방식

포트 스캔 실행 흐름은 아래와 같습니다.

1. 사용자가 `--host` 또는 `--target-cidr-file`로 대상을 전달합니다.
2. CLI가 대상 목록을 파일 또는 CIDR 확장 결과로 정규화합니다.
3. 스캔 백엔드를 결정합니다.
   - `--backend naabu`
   - `--backend tcp`
   - `--backend auto`면 `naabu` 존재 여부를 보고 자동 선택
4. 스캐너가 열린 포트를 찾습니다.
5. 결과를 이전 상태 파일과 비교해 신규 포트를 판별합니다.
6. `nmap`이 가능하면 서비스 식별을 추가하고, 불가능하면 포트-only 결과를 반환합니다.
7. 상태 파일을 저장합니다.
8. 결과를 JSON으로 출력합니다.

## 6. Docker 테스트 랩

### 6.1 구성 서비스

| Service | Published Port | Internal Port | IP | 역할 |
| --- | --- | --- | --- | --- |
| web | 80, 443 | 80, 443 | 192.168.100.10 | Apache 테스트 대상 |
| mysql | 3306 | 3306 | 192.168.100.20 | 외부 접속 가능한 MySQL |
| redis | 6379 | 6379 | 192.168.100.30 | 인증 없는 Redis |
| ssh | 22 | 2222 | 192.168.100.40 | SSH 테스트 대상 |
| shellshock | 8080 | 8080 | 192.168.100.50 | 포트 스캔 검증용 8080 타깃 |

### 6.2 중요한 구현 메모

- Docker Desktop 환경에서는 호스트가 브리지 서브넷을 직접 스캔하지 못하는 경우가 많습니다.
- 그래서 실제 검증은 `127.0.0.1`의 published port를 기준으로 수행했습니다.
- SSH 서비스는 `linuxserver/openssh-server` 이미지 특성상 내부 포트가 `2222`이고, 외부에는 `22`로 publish 됩니다.
- 원래 `vulnerables/cve-2014-6271` 이미지를 쓰려 했지만 실환경에서 `Exited (139)`로 죽었기 때문에, 포트 스캔 검증이 가능한 안정적인 `8080` 타깃으로 교체했습니다.

즉:
- "포트 스캔 검증" 목적은 충족합니다.
- "실제 Shellshock 취약점 재현"은 현재 범위에 포함하지 않습니다.

## 7. 실행 방법

### 7.1 사전 준비

필수:
- Python 3.10+
- Docker Desktop

선택:
- `naabu`
- `nmap`

### 7.2 랩 기동

```powershell
cd D:\3rd_Project\portscanner
.\portscanner.ps1 lab-up
```

또는

```powershell
docker compose up -d --build
```

### 7.3 랩 종료

```powershell
.\portscanner.ps1 lab-down
```

### 7.4 단일 호스트 스캔

```powershell
.\portscanner.ps1 scan --host 127.0.0.1 --backend tcp --ports 22,80,443,3306,6379,8080 --skip-nmap
```

### 7.5 CIDR 파일 스캔

예시 파일:

```text
192.168.100.0/24
10.0.0.5/32
```

실행:

```powershell
.\portscanner.ps1 scan --target-cidr-file .\target_cidr.txt --backend auto --ports 1-65535
```

### 7.6 결과를 파일로 저장

```powershell
.\portscanner.ps1 scan `
  --host 127.0.0.1 `
  --backend tcp `
  --ports 22,80,443,3306,6379,8080 `
  --skip-nmap `
  --json-out .\scan-result.json
```

### 7.7 Nmap 정밀분석 포함

`nmap`이 설치되어 있으면 `--skip-nmap`을 빼고 실행하면 됩니다.

```powershell
.\portscanner.ps1 scan --host 127.0.0.1 --backend auto --ports 22,80,443,3306,6379,8080
```

동작:
- `nmap`이 있으면 서비스 식별까지 수행
- `nmap`이 없으면 포트-only 결과로 자동 처리

## 8. CLI 인자 설명

| Option | 설명 |
| --- | --- |
| `--host` | 단일 호스트/IP. 반복 가능 |
| `--target-cidr-file` | `target_cidr.txt` 형식의 대상 파일 |
| `--backend` | `auto`, `naabu`, `tcp` |
| `--ports` | `1-65535`, `22,80,443`, `22 80 443` 모두 가능 |
| `--timeout` | TCP backend 연결 타임아웃 |
| `--concurrency` | TCP backend worker 수 |
| `--rate` | `naabu` rate |
| `--state-path` | 상태 저장 파일 경로 |
| `--json-out` | 결과 JSON 파일 경로 |
| `--skip-nmap` | 서비스 식별 생략 |
| `lab-up` | 테스트 랩 기동 |
| `lab-down` | 테스트 랩 종료 |

## 9. 출력 형식

기본 출력은 JSON입니다.

예시:

```json
{
  "backend": "TCPConnectScanner",
  "new_assets": [
    { "ip": "127.0.0.1", "port": 22 },
    { "ip": "127.0.0.1", "port": 80 }
  ],
  "open_ports": {
    "127.0.0.1": [22, 80, 443, 3306, 6379, 8080]
  },
  "targets": ["127.0.0.1"]
}
```

상태 파일 예시:

```json
{
  "127.0.0.1": [22, 80, 443, 3306, 6379, 8080]
}
```

## 10. 저장소 구조

```text
portscanner/
├─ docker-compose.yml
├─ portscanner.ps1
├─ portscanner.cmd
├─ portscanner_cli.py
├─ target_cidr.txt.example
├─ src/
│  └─ portscanner/
│     ├─ cli.py
│     ├─ pipeline.py
│     ├─ tcp_connect_scanner.py
│     ├─ naabu_wrapper.py
│     ├─ nmap_scanner.py
│     ├─ banner_parser.py
│     ├─ shadow_it.py
│     └─ analysis_api.py
├─ docker/
│  ├─ apache/
│  └─ shellshock/
└─ tests/
```

## 11. 실제 검증 결과

이 저장소는 코드 리뷰 수준이 아니라 실제로 아래 항목을 실행해 검증했습니다.

### 11.1 자동 테스트

```powershell
python -m pytest
```

결과:
- `19 passed`

### 11.2 실제 Docker 랩 기동

실행:

```powershell
docker compose up -d --build
docker ps
```

확인한 서비스:
- `easm-shellshock`
- `easm-ssh`
- `easm-mysql`
- `easm-web`
- `easm-redis`

### 11.3 실제 포트 스캔

실행:

```powershell
.\portscanner.ps1 scan --host 127.0.0.1 --backend tcp --ports 22,80,443,3306,6379,8080 --skip-nmap
```

확인된 open ports:
- `22`
- `80`
- `443`
- `3306`
- `6379`
- `8080`

같은 상태 파일로 다시 실행했을 때:
- `new_assets`가 빈 배열로 나왔고
- 상태 비교가 실제로 동작함을 확인했습니다.

## 12. 구현상 주의사항 / 제한사항

- 이 저장소는 "포트 스캔" 기준으로는 실행 가능하지만, `naabu`와 `nmap`는 번들되어 있지 않습니다.
- `auto` backend는 `naabu`가 없으면 자동으로 TCP connect backend로 fallback 됩니다.
- Docker Desktop 환경에서는 localhost published port를 스캔하는 방식이 가장 현실적입니다.
- PowerShell에서 포트 인자 분해 이슈를 피하기 위해 `--ports 22,80,443`와 `--ports 22 80 443`를 모두 지원합니다.
- Shellshock 서비스는 실제 취약점 재현용이 아니라 `8080/tcp` 테스트 타깃입니다.
- 법적/윤리적 이유로 실제 외부망이 아닌 통제된 테스트 환경에서만 사용해야 합니다.

## 13. 앞으로 확장할 수 있는 방향

- CLI에서 Telegram/API 옵션 직접 지원
- Nmap 결과를 리포트 파일로 내보내기
- 배너 캡처 / 웹 스크린샷 연계
- 더 큰 범위 스캔에 대한 batching/worker tuning
- Linux/macOS용 direct launcher 추가

## 14. 빠른 시작 요약

```powershell
cd D:\3rd_Project\portscanner
.\portscanner.ps1 lab-up
.\portscanner.ps1 scan --host 127.0.0.1 --backend tcp --ports 22,80,443,3306,6379,8080 --skip-nmap
python -m pytest
```
