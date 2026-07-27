"""
우선순위 산정: CVSS(심각도) + EPSS(악용 확률) + CISA KEV(실제 악용 중).

목표는 "CVE 나열"이 아니라 "지금 당장 뭘 고쳐야 하나"를 뽑는 것.
방어자 업무를 줄이는 핵심 로직이라 규칙을 투명하게 노출한다.

우선순위 규칙 (위에서부터 매칭):
  P0 즉시    : KEV 등재 (실제 악용 중) 또는 (CVSS>=9 이고 EPSS>=0.5)
  P1 높음    : CVSS>=9  또는 (CVSS>=7 이고 EPSS>=0.5)
  P2 보통    : CVSS>=7  또는 EPSS>=0.1
  P3 낮음    : 그 외
근거 데이터가 없으면 보수적으로 라벨(HIGH/CRITICAL)로 대체 판단.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import httpx

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_LABEL_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 3.0}

PRIORITY_NAMES = {0: "P0 즉시", 1: "P1 높음", 2: "P2 보통", 3: "P3 낮음"}


@dataclass
class Scored:
    finding: "object"          # osv.Finding
    cve: Optional[str]
    cvss: Optional[float]
    epss: Optional[float]      # 0~1 확률
    epss_percentile: Optional[float]
    in_kev: bool
    priority: int              # 0~3
    reason: str


def cvss_base_score(vectors: list[str]) -> Optional[float]:
    """CVSS 벡터 문자열들 중 최고 base score 반환."""
    from cvss import CVSS3, CVSS4
    best = None
    for vec in vectors:
        v = vec.strip()
        score = None
        try:
            if v.startswith("CVSS:4"):
                score = float(CVSS4(v).base_score)
            elif v.startswith("CVSS:3"):
                score = float(CVSS3(v).scores()[0])
            else:
                # 숫자만 온 경우
                score = float(v)
        except Exception:
            continue
        if score is not None and (best is None or score > best):
            best = score
    return best


async def _fetch_epss(client: httpx.AsyncClient, cves: list[str]) -> dict:
    """CVE -> (epss, percentile). 콤마로 배치 조회."""
    out: dict[str, tuple[float, float]] = {}
    for start in range(0, len(cves), 100):
        chunk = cves[start:start + 100]
        try:
            r = await client.get(EPSS_API, params={"cve": ",".join(chunk)}, timeout=20)
            r.raise_for_status()
            for row in r.json().get("data", []):
                cve = row.get("cve")
                if cve:
                    out[cve.upper()] = (
                        float(row.get("epss", 0) or 0),
                        float(row.get("percentile", 0) or 0),
                    )
        except (httpx.HTTPError, ValueError):
            continue
    return out


async def _fetch_kev(client: httpx.AsyncClient) -> set[str]:
    try:
        r = await client.get(KEV_FEED, timeout=30)
        r.raise_for_status()
        return {
            v.get("cveID", "").upper()
            for v in r.json().get("vulnerabilities", [])
            if v.get("cveID")
        }
    except (httpx.HTTPError, ValueError):
        return set()


def _priority(cvss: Optional[float], epss: Optional[float], in_kev: bool,
              label: str) -> tuple[int, str]:
    c = cvss
    if c is None and label:
        c = _LABEL_SCORE.get(label.upper())
    e = epss or 0.0

    if in_kev:
        return 0, "CISA KEV 등재 — 실제 악용 중"
    if c is not None and c >= 9 and e >= 0.5:
        return 0, f"CVSS {c:.1f} + EPSS {e*100:.0f}% (악용 임박)"
    if c is not None and c >= 9:
        return 1, f"CVSS {c:.1f} (Critical)"
    if c is not None and c >= 7 and e >= 0.5:
        return 1, f"CVSS {c:.1f} + EPSS {e*100:.0f}%"
    if c is not None and c >= 7:
        return 2, f"CVSS {c:.1f} (High)"
    if e >= 0.1:
        return 2, f"EPSS {e*100:.0f}% (악용 관측 상승)"
    if c is not None:
        return 3, f"CVSS {c:.1f}"
    return 3, "심각도 정보 부족"


async def enrich_async(findings, http_client: Optional[httpx.AsyncClient] = None):
    if not findings:
        return []
    own = http_client is None
    client = http_client or httpx.AsyncClient(headers={"User-Agent": "DepSentinel/0.1"})
    try:
        cves = sorted({f.vuln.cve for f in findings if f.vuln.cve})
        epss_map, kev_set = await asyncio.gather(
            _fetch_epss(client, cves) if cves else _noop_dict(),
            _fetch_kev(client),
        )
    finally:
        if own:
            await client.aclose()

    scored: list[Scored] = []
    for f in findings:
        cve = f.vuln.cve
        cvss = cvss_base_score(f.vuln.cvss_vectors)
        epss, pct = (epss_map.get(cve, (None, None)) if cve else (None, None))
        in_kev = bool(cve and cve in kev_set)
        prio, reason = _priority(cvss, epss, in_kev, f.vuln.severity_label)
        scored.append(Scored(f, cve, cvss, epss, pct, in_kev, prio, reason))

    # P0 -> P3, 그 안에서 EPSS 높은 순
    scored.sort(key=lambda s: (s.priority, -(s.epss or 0), -(s.cvss or 0)))
    return scored


async def _noop_dict():
    return {}


def enrich(findings):
    return asyncio.run(enrich_async(findings))
