"""
DepSentinel — 보안 담당자를 위한 SBOM 취약점 우선순위 MCP 서버.

노출 tool:
  - analyze_dependencies : SBOM/매니페스트 -> 우선순위화된 위협 리포트 (메인)
  - check_package        : 단일 패키지 즉석 점검

설계 원칙:
  - 나열이 아니라 우선순위 (CVSS + EPSS + CISA KEV)
  - 정식 SBOM 없어도 매니페스트로 진입 가능 (사각지대 대응)
  - 근거(링크/점수) 동봉, 추정 버전은 표시 — 오탐 판단은 사람이
"""
from __future__ import annotations

import os
import httpx
from mcp.server.fastmcp import FastMCP

from .sbom import parse, Component
from .osv import scan_async
from .enrich import enrich_async, PRIORITY_NAMES

mcp = FastMCP(
    "DepSentinel",
    host="0.0.0.0",
    port=int(os.getenv("PORT", "8000")),
)

_MAX_DETAIL = 30       # 리포트에 상세 표기할 최대 건수
_UA = {"User-Agent": "DepSentinel/0.1 (+security-sbom-mcp)"}

DISCLAIMER = (
    "공개 취약점 advisory(OSV/EPSS/CISA KEV) 기반 best-effort 점검입니다. "
    "버전 매칭 특성상 오탐/미탐이 있을 수 있어 결과는 근거 링크로 확인이 필요하며, "
    "전체 보안 프로그램을 대체하지 않습니다."
)


def _scored_to_dict(s) -> dict:
    f = s.finding
    v = f.vuln
    return {
        "priority": PRIORITY_NAMES[s.priority],
        "reason": s.reason,
        "package": f"{f.ecosystem}:{f.name}@{f.version}",
        "vuln_id": v.id,
        "cve": s.cve,
        "cvss": round(s.cvss, 1) if s.cvss is not None else None,
        "epss": round(s.epss, 4) if s.epss is not None else None,
        "in_kev": s.in_kev,
        "summary": v.summary or (v.details[:160] if v.details else ""),
        "fixed_versions": v.fixed_versions,
        "approximate_version": f.approximate_version,
        "references": v.references[:3],
    }


def _build_markdown(parsed_fmt, stats, scored) -> str:
    counts = {0: 0, 1: 0, 2: 0, 3: 0}
    for s in scored:
        counts[s.priority] += 1
    lines = []
    lines.append(f"**분석 결과** (입력 형식: {parsed_fmt})")
    lines.append(
        f"- 점검 컴포넌트 {stats.get('components_scanned', 0)}개 중 "
        f"{stats.get('components_affected', 0)}개에서 "
        f"{stats.get('unique_vulns', 0)}건의 취약점 발견"
    )
    lines.append(
        f"- 우선순위: P0 즉시 {counts[0]} · P1 높음 {counts[1]} · "
        f"P2 보통 {counts[2]} · P3 낮음 {counts[3]}"
    )
    urgent = [s for s in scored if s.priority <= 1]
    if urgent:
        lines.append("\n**지금 먼저 볼 것 (P0~P1)**")
        for s in urgent[:_MAX_DETAIL]:
            f = s.finding
            fix = f" → {f.vuln.fixed_versions[0]} 이상으로 업그레이드" if f.vuln.fixed_versions else ""
            kev = " [KEV]" if s.in_kev else ""
            approx = " (버전 추정)" if f.approximate_version else ""
            lines.append(
                f"- **{PRIORITY_NAMES[s.priority]}**{kev} `{f.name}@{f.version}`{approx} — "
                f"{s.cve or f.vuln.id}: {s.reason}{fix}"
            )
    else:
        lines.append("\nP0~P1 등급의 즉시 조치 대상은 없습니다.")
    lines.append(f"\n_{DISCLAIMER}_")
    return "\n".join(lines)


async def _run(content: str, fmt: str) -> dict:
    parsed = parse(content, fmt)
    if not parsed.components:
        return {
            "ok": False,
            "message": "파싱된 컴포넌트가 없습니다. 형식/버전 표기를 확인하세요.",
            "source_format": parsed.source_format,
            "skipped": parsed.skipped[:20],
        }
    async with httpx.AsyncClient(headers=_UA) as client:
        findings, stats = await scan_async(parsed.components, http_client=client)
        scored = await enrich_async(findings, http_client=client)

    detailed = [_scored_to_dict(s) for s in scored[:_MAX_DETAIL]]
    return {
        "ok": True,
        "source_format": parsed.source_format,
        "stats": stats,
        "priority_counts": {
            PRIORITY_NAMES[p]: sum(1 for s in scored if s.priority == p)
            for p in range(4)
        },
        "findings": detailed,
        "findings_truncated": max(0, len(scored) - len(detailed)),
        "skipped_inputs": parsed.skipped[:20],
        "summary_markdown": _build_markdown(parsed.source_format, stats, scored),
        "disclaimer": DISCLAIMER,
    }


@mcp.tool(
    title="의존성 취약점 분석",
    description=(
        "SBOM(CycloneDX/SPDX JSON) 또는 매니페스트(requirements.txt, package.json, "
        "package-lock.json, pom.xml, purl 목록)를 받아 OSV.dev 로 취약점을 대조하고 "
        "CVSS·EPSS·CISA KEV 로 우선순위를 매긴 리포트를 반환한다. "
        "format 은 보통 auto 로 두면 된다."
    ),
)
async def analyze_dependencies(content: str, format: str = "auto") -> dict:
    """content: SBOM/매니페스트 원문. format: auto|cyclonedx|spdx|requirements|package_json|pom|purl"""
    try:
        return await _run(content, format)
    except ValueError as e:
        return {"ok": False, "message": str(e)}
    except httpx.HTTPError as e:
        return {"ok": False, "message": f"외부 데이터 조회 실패: {e}"}


@mcp.tool(
    title="단일 패키지 점검",
    description="ecosystem(PyPI/npm/Maven/Go/RubyGems/crates.io/NuGet 등), name, version 으로 단일 패키지의 취약점과 우선순위를 즉석 점검한다.",
)
async def check_package(ecosystem: str, name: str, version: str) -> dict:
    comp = Component(ecosystem=ecosystem, name=name, version=version)
    async with httpx.AsyncClient(headers=_UA) as client:
        findings, stats = await scan_async([comp], http_client=client)
        scored = await enrich_async(findings, http_client=client)
    if not scored:
        return {"ok": True, "package": f"{ecosystem}:{name}@{version}",
                "vulnerable": False, "message": "알려진 취약점 없음 (OSV 기준)",
                "disclaimer": DISCLAIMER}
    return {
        "ok": True,
        "package": f"{ecosystem}:{name}@{version}",
        "vulnerable": True,
        "findings": [_scored_to_dict(s) for s in scored],
        "disclaimer": DISCLAIMER,
    }


def main():
    # 배포: streamable-http (Kakao Cloud 등). 로컬 테스트: stdio.
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
