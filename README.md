# DepSentinel — SBOM 취약점 우선순위 MCP

보안 담당자를 위한 MCP 서버. SBOM 또는 매니페스트를 넣으면, 쓰고 있는
오픈소스에 뭐가 위험한지 **나열이 아니라 우선순위로** 뽑아준다.

- **왜:** SCA 도구는 CVE를 수백 개 뱉는다. 정작 필요한 건 "이 중 지금 당장
  고칠 3개"다. 그 판단을 자동화해 방어자 업무를 줄인다.
- **누구:** 보안팀이 없거나 얇은 중소기업 등 보안 사각지대까지.

## 어떻게 우선순위를 매기나

세 신호를 합친다:
- **CVSS** — 취약점 자체의 심각도 (OSV 제공 벡터에서 base score 계산)
- **EPSS** — 향후 30일 내 실제 악용될 확률 (FIRST.org)
- **CISA KEV** — 지금 현실에서 악용 중인 취약점 목록

규칙(투명 공개, `enrich.py`):

| 등급 | 조건 |
|------|------|
| **P0 즉시** | KEV 등재, 또는 CVSS≥9 이고 EPSS≥50% |
| **P1 높음** | CVSS≥9, 또는 CVSS≥7 이고 EPSS≥50% |
| **P2 보통** | CVSS≥7, 또는 EPSS≥10% |
| **P3 낮음** | 그 외 |

## 노출 tool

- `analyze_dependencies(content, format="auto")` — SBOM/매니페스트 원문을 받아
  우선순위 리포트(구조화 데이터 + `summary_markdown`) 반환. **메인.**
- `check_package(ecosystem, name, version)` — 단일 패키지 즉석 점검.

## 지원 입력 형식 (`format=auto` 로 자동 판별)

- CycloneDX JSON / SPDX JSON  (purl 우선)
- `requirements.txt` (PyPI, `==` 고정 버전)
- `package.json` / `package-lock.json` (npm; lock 파일이 정확)
- `pom.xml` (Maven, best-effort)
- purl 목록 (한 줄에 하나)

> 정식 SBOM이 없어도 매니페스트를 그대로 던질 수 있게 한 게 사각지대 대응 포인트.

## 설치

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .          # depsentinel / depsentinel-scan 커맨드 설치
# 또는: pip install -r requirements.txt
```

## 테스트

```bash
# 1) 오프라인 로직 검증 (네트워크 불필요) — 파서/CVSS/우선순위
python -m depsentinel.smoke_test

# 2) 로컬 스캔 — MCP 클라이언트 없이 파일 하나로 전체 파이프라인 확인
depsentinel-scan samples/sample_requirements.txt
depsentinel-scan samples/sample_cyclonedx.json --all      # P2/P3 까지 전부
#   (OSV/EPSS/CISA 로 아웃바운드가 필요 — 사내망이면 방화벽 허용 확인)

# 3) MCP 클라이언트로 인터랙티브 점검 (MCP Inspector)
MCP_TRANSPORT=stdio npx @modelcontextprotocol/inspector python -m depsentinel.server
```

## 실행 (서버)

```bash
# 로컬 (stdio) — Claude Desktop 등에 붙일 때
MCP_TRANSPORT=stdio python -m depsentinel.server

# 배포 (streamable-http) — Kakao Cloud 등. 기본값.
python -m depsentinel.server
# 또는 설치된 커맨드로:  depsentinel
```

## PlayMCP / Kakao Cloud 등록 메모

- 서버는 `streamable-http` 트랜스포트로 뜬다. 외부에서 접근할 HTTP 엔드포인트를
  PlayMCP에 등록하면 된다.
- 아웃바운드로 `api.osv.dev`, `api.first.org`, `www.cisa.gov` 세 곳에 접근해야 한다.
  방화벽/보안그룹 아웃바운드 허용 필요.
- KEV 피드는 매 호출마다 받는다. 트래픽 많으면 캐싱(예: 6h TTL) 붙일 것 — TODO 참고.

## 솔직한 한계 (심사 "안정성" 대비)

- **이 저장소에서 검증된 것:** 파싱, CVSS 계산, 우선순위 규칙, 에러 처리, tool 등록.
  (오프라인 스모크 테스트 통과)
- **아직 라이브로 못 돌려본 것:** OSV/EPSS/KEV 실호출. 빌드 환경에서 해당 도메인
  아웃바운드가 막혀 있었다. 네트워크 되는 환경에서 `analyze_dependencies`로 최종 확인 필요.
- **오탐/미탐:** 버전 매칭은 원래 노이즈가 있다(버전 range, 배포판 백포트 패치 등).
  결과에 근거 링크와 CVSS/EPSS/KEV 원점수를 같이 실어 사람이 확인하게 설계했다.
  `package.json`의 range 버전은 `approximate_version=true`로 표시한다.
- **KEV 매칭:** KEV는 CVE 기준이라, CVE 별칭이 없는 취약점(GHSA-only)은 KEV 대조에서
  빠질 수 있다. 이 경우 CVSS/EPSS로만 판단한다.
- **민감정보:** SBOM은 회사 기술스택이 드러나는 공급망 정보다. 서버는 SBOM을
  저장하지 않고 요청 처리 후 버린다(예선 스코프). 저장형(본선)으로 갈 땐 암호화·접근통제 필요.
- 공개 advisory 기반 best-effort이며 전체 보안 프로그램을 대체하지 않는다.

## 로드맵 (본선 방향)

예선은 온디맨드다. "위협 생기면 알림"은 MCP(요청-응답)만으론 안 되고 별도 백엔드가 필요:

1. SBOM 저장 + 주기적(예: 일 1회) 최신 피드 재대조
2. 새로 뜬 P0/P1이 있으면 **카카오톡 메시지 API로 푸시 알림**
3. KEV/EPSS 캐싱, ISMS-P 항목 매핑, KISA 보안공지(KNVD) 소스 추가

---

구조: `sbom.py`(파싱) · `osv.py`(대조) · `enrich.py`(우선순위) · `server.py`(MCP tool) · `cli.py`(로컬 테스트)
