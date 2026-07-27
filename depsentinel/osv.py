"""
OSV.dev 클라이언트.

흐름:
  1) /v1/querybatch 로 (패키지, 버전) 배치 대조 -> 취약점 ID 만 회수
  2) 유니크한 ID 들에 대해 /v1/vulns/{id} 로 상세 조회
     (severity/CVSS 벡터, aliases(CVE), affected 버전, 참조 링크)

querybatch 는 응답이 가벼워 대량 SBOM 에 유리하다. 상세는 발견된 것만 가져온다.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import httpx

OSV_API = "https://api.osv.dev"
QUERYBATCH = f"{OSV_API}/v1/querybatch"
VULN = f"{OSV_API}/v1/vulns"

_BATCH = 200          # querybatch 요청당 최대 쿼리 수
_DETAIL_CONCURRENCY = 8


@dataclass
class Vuln:
    id: str
    aliases: list[str] = field(default_factory=list)   # CVE 등
    summary: str = ""
    details: str = ""
    cvss_vectors: list[str] = field(default_factory=list)
    severity_label: str = ""       # DB 제공 라벨 (CRITICAL/HIGH...)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def cve(self) -> Optional[str]:
        for a in self.aliases:
            if a.upper().startswith("CVE-"):
                return a.upper()
        return None


@dataclass
class Finding:
    ecosystem: str
    name: str
    version: str
    vuln: Vuln
    approximate_version: bool = False


def _pkg_query(eco: str, name: str, version: str) -> dict:
    return {"version": version, "package": {"name": name, "ecosystem": eco}}


async def _fetch_detail(client: httpx.AsyncClient, vuln_id: str,
                        sem: asyncio.Semaphore) -> Optional[Vuln]:
    async with sem:
        try:
            r = await client.get(f"{VULN}/{vuln_id}", timeout=20)
            r.raise_for_status()
        except httpx.HTTPError:
            return None
    data = r.json()
    vectors, label = [], ""
    for sev in data.get("severity", []):
        if sev.get("score"):
            vectors.append(sev["score"])
    db = data.get("database_specific", {}) or {}
    label = db.get("severity", "") or ""
    fixed = []
    for aff in data.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
    refs = [r.get("url", "") for r in data.get("references", []) if r.get("url")]
    return Vuln(
        id=data.get("id", vuln_id),
        aliases=data.get("aliases", []) or [],
        summary=data.get("summary", "") or "",
        details=(data.get("details", "") or "")[:600],
        cvss_vectors=vectors,
        severity_label=label,
        fixed_versions=sorted(set(fixed)),
        references=refs[:5],
    )


async def scan_async(components, http_client: Optional[httpx.AsyncClient] = None):
    """Component 목록 -> Finding 목록. 상세는 발견된 취약점만 조회."""
    from .sbom import Component  # 타입 힌트용, 순환 안전

    comps = list(components)
    if not comps:
        return [], {}

    own = http_client is None
    client = http_client or httpx.AsyncClient(headers={"User-Agent": "DepSentinel/0.1"})
    try:
        # 1) 배치 대조
        # 각 컴포넌트 -> 취약점 ID 리스트
        comp_to_ids: list[list[str]] = [[] for _ in comps]
        for start in range(0, len(comps), _BATCH):
            chunk = comps[start:start + _BATCH]
            payload = {"queries": [_pkg_query(c.ecosystem, c.name, c.version) for c in chunk]}
            r = await client.post(QUERYBATCH, json=payload, timeout=30)
            r.raise_for_status()
            results = r.json().get("results", [])
            for i, res in enumerate(results):
                ids = [v["id"] for v in (res.get("vulns") or []) if v.get("id")]
                comp_to_ids[start + i] = ids

        # 2) 유니크 ID 상세 조회
        unique_ids = sorted({vid for ids in comp_to_ids for vid in ids})
        sem = asyncio.Semaphore(_DETAIL_CONCURRENCY)
        details = await asyncio.gather(
            *[_fetch_detail(client, vid, sem) for vid in unique_ids]
        )
        by_id = {v.id: v for v in details if v}

        findings: list[Finding] = []
        for comp, ids in zip(comps, comp_to_ids):
            for vid in ids:
                v = by_id.get(vid)
                if v:
                    findings.append(Finding(
                        ecosystem=comp.ecosystem, name=comp.name,
                        version=comp.version, vuln=v,
                        approximate_version=getattr(comp, "approximate", False),
                    ))
        stats = {
            "components_scanned": len(comps),
            "components_affected": sum(1 for ids in comp_to_ids if ids),
            "unique_vulns": len(by_id),
        }
        return findings, stats
    finally:
        if own:
            await client.aclose()


def scan(components):
    """동기 래퍼."""
    return asyncio.run(scan_async(components))
