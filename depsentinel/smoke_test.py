"""
오프라인 스모크 테스트 — 네트워크 없이 파싱/CVSS/우선순위 로직만 검증.
실행: python -m depsentinel.smoke_test
(라이브 OSV 대조는 네트워크 되는 환경에서 analyze_dependencies 로 확인)
"""
from depsentinel import sbom, enrich
from depsentinel.enrich import _priority


def test_parsers():
    r = sbom.parse("django==3.2.0\nflask>=1.0  # range\nrequests==2.25.1")
    names = {c.name for c in r.components}
    assert names == {"django", "requests"}, names
    assert any("flask" in s for s in r.skipped)

    r2 = sbom.parse('{"dependencies":{"lodash":"^4.17.19"}}')
    assert r2.components[0].approximate is True

    r3 = sbom.parse("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    c = r3.components[0]
    assert c.ecosystem == "Maven" and c.name == "org.apache.logging.log4j:log4j-core"
    print("[ok] parsers")


def test_cvss():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert enrich.cvss_base_score([v]) == 10.0
    print("[ok] cvss")


def test_priority():
    assert _priority(7.5, 0.02, True, "HIGH")[0] == 0       # KEV -> P0
    assert _priority(9.8, 0.7, False, "CRITICAL")[0] == 0    # crit+epss -> P0
    assert _priority(9.0, 0.01, False, "CRITICAL")[0] == 1   # crit -> P1
    assert _priority(7.2, 0.01, False, "HIGH")[0] == 2       # high -> P2
    assert _priority(4.0, 0.3, False, "MEDIUM")[0] == 2      # epss>=0.1 -> P2
    assert _priority(3.0, 0.001, False, "LOW")[0] == 3       # -> P3
    assert _priority(None, None, False, "CRITICAL")[0] == 1  # label fallback
    print("[ok] priority")


if __name__ == "__main__":
    test_parsers()
    test_cvss()
    test_priority()
    print("\n모든 오프라인 테스트 통과.")
