"""
로컬 테스트용 CLI — MCP 클라이언트 없이 파일 하나 넣고 결과 확인.

사용:
    python -m depsentinel.cli samples/sample_requirements.txt
    python -m depsentinel.cli samples/sample_cyclonedx.json --format cyclonedx

(OSV/EPSS/CISA 로 아웃바운드가 필요하므로 네트워크 되는 환경에서 실행)
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from .server import analyze_dependencies


def main() -> None:
    p = argparse.ArgumentParser(
        prog="depsentinel-scan",
        description="SBOM/매니페스트 파일을 스캔해 우선순위 리포트를 출력한다.",
    )
    p.add_argument("path", help="SBOM 또는 매니페스트 파일 경로")
    p.add_argument(
        "--format", default="auto",
        help="auto|cyclonedx|spdx|requirements|package_json|pom|purl (기본 auto)",
    )
    p.add_argument("--all", action="store_true", help="P2/P3 포함 전체 findings 출력")
    args = p.parse_args()

    try:
        with open(args.path, encoding="utf-8") as fh:
            content = fh.read()
    except OSError as e:
        print(f"파일 읽기 실패: {e}", file=sys.stderr)
        sys.exit(1)

    result = asyncio.run(analyze_dependencies(content, args.format))

    if not result.get("ok"):
        print(f"[실패] {result.get('message')}", file=sys.stderr)
        if result.get("skipped"):
            print("건너뛴 입력:", ", ".join(result["skipped"]), file=sys.stderr)
        sys.exit(2)

    print(result["summary_markdown"])

    findings = result.get("findings", [])
    if args.all and findings:
        print("\n── 전체 findings ──")
        for f in findings:
            kev = " [KEV]" if f.get("in_kev") else ""
            fix = f" → fix: {f['fixed_versions'][0]}" if f.get("fixed_versions") else ""
            print(f"  {f['priority']}{kev}  {f['package']}  "
                  f"{f.get('cve') or f['vuln_id']}  ({f['reason']}){fix}")
    if result.get("findings_truncated"):
        print(f"\n(+{result['findings_truncated']}건 더 있음 — 상위 {len(findings)}건만 표시)")


if __name__ == "__main__":
    main()
