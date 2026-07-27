"""
SBOM / 매니페스트 파서.

지원 입력:
  - CycloneDX JSON  (components[].purl 또는 name+version)
  - SPDX JSON       (packages[].name/versionInfo, externalRefs 의 purl)
  - requirements.txt (PyPI)
  - package.json / package-lock.json (npm)
  - pom.xml (Maven, best-effort)
  - purl 목록 (한 줄에 하나: pkg:pypi/django@3.2)

정식 SBOM 이 없는 중소기업/사각지대도 던질 수 있게, 매니페스트 파일을
그대로 받아 정규화하는 걸 목표로 한다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from xml.etree import ElementTree as ET


# purl type -> OSV ecosystem
PURL_TO_OSV = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "gem": "RubyGems",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
}


@dataclass
class Component:
    ecosystem: str          # OSV ecosystem 이름 (PyPI, npm, Maven ...)
    name: str
    version: str
    purl: Optional[str] = None
    approximate: bool = False   # 버전이 range 에서 추정된 경우 True

    def key(self) -> tuple:
        return (self.ecosystem, self.name, self.version)


@dataclass
class ParseResult:
    source_format: str
    components: list[Component] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)   # 파싱 못한 항목 (버전 없음 등)

    def dedup(self) -> "ParseResult":
        seen = set()
        out = []
        for c in self.components:
            if c.key() in seen:
                continue
            seen.add(c.key())
            out.append(c)
        self.components = out
        return self


# --------------------------------------------------------------------------- #
# purl
# --------------------------------------------------------------------------- #
def parse_purl(purl: str) -> Optional[Component]:
    # pkg:type/namespace/name@version?qualifiers#subpath
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:]
    body = body.split("#", 1)[0]
    body = body.split("?", 1)[0]
    if "@" not in body:
        return None
    path, version = body.rsplit("@", 1)
    if "/" not in path:
        return None
    ptype, rest = path.split("/", 1)
    ptype = ptype.lower()
    eco = PURL_TO_OSV.get(ptype)
    if not eco:
        return None
    # maven: namespace/name -> namespace:name
    if ptype == "maven" and "/" in rest:
        ns, name = rest.rsplit("/", 1)
        name = f"{ns}:{name}"
    elif "/" in rest:
        # npm scoped: @scope/name
        name = rest
    else:
        name = rest
    version = version.strip()
    try:
        from urllib.parse import unquote
        name = unquote(name)
        version = unquote(version)
    except Exception:
        pass
    if not version:
        return None
    return Component(ecosystem=eco, name=name, version=version, purl=purl)


# --------------------------------------------------------------------------- #
# CycloneDX / SPDX
# --------------------------------------------------------------------------- #
def _from_cyclonedx(data: dict) -> ParseResult:
    res = ParseResult(source_format="CycloneDX")
    for comp in data.get("components", []):
        purl = comp.get("purl")
        if purl:
            c = parse_purl(purl)
            if c:
                res.components.append(c)
                continue
        name = comp.get("name")
        version = comp.get("version")
        if name and version:
            eco = _guess_eco_from_cdx(comp)
            if eco:
                res.components.append(Component(eco, name, version))
            else:
                res.skipped.append(f"{name}@{version} (ecosystem 불명)")
        elif name:
            res.skipped.append(f"{name} (버전 없음)")
    return res.dedup()


def _guess_eco_from_cdx(comp: dict) -> Optional[str]:
    # CycloneDX 는 명시적 ecosystem 필드가 없어 purl 없으면 추정 어려움.
    return None


def _from_spdx(data: dict) -> ParseResult:
    res = ParseResult(source_format="SPDX")
    for pkg in data.get("packages", []):
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        if purl:
            c = parse_purl(purl)
            if c:
                res.components.append(c)
                continue
        name = pkg.get("name")
        version = pkg.get("versionInfo")
        if name and version and version != "NOASSERTION":
            res.skipped.append(f"{name}@{version} (purl 없음, ecosystem 불명)")
        elif name:
            res.skipped.append(f"{name} (버전 없음)")
    return res.dedup()


# --------------------------------------------------------------------------- #
# 매니페스트
# --------------------------------------------------------------------------- #
_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-]+)"
)


def _from_requirements(text: str) -> ParseResult:
    res = ParseResult(source_format="requirements.txt")
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        line = line.split(";", 1)[0].strip()  # 환경 마커 제거
        if not line or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if m:
            res.components.append(Component("PyPI", m.group(1), m.group(3)))
        elif re.match(r"^[A-Za-z0-9_.\-]+\s*[<>~!]=?", line):
            res.skipped.append(f"{line} (고정 버전 아님 ==만 지원)")
    return res.dedup()


_NPM_VER = re.compile(r"[0-9][0-9A-Za-z.\-+]*")


def _clean_npm_version(spec: str) -> Optional[tuple[str, bool]]:
    spec = spec.strip()
    if spec in ("*", "latest", "") or spec.startswith(("http", "git", "file:", "workspace:")):
        return None
    approx = bool(re.match(r"^[\^~><=]", spec)) or " " in spec or "||" in spec
    m = _NPM_VER.search(spec)
    if not m:
        return None
    return m.group(0), approx


def _from_package_json(data: dict) -> ParseResult:
    res = ParseResult(source_format="package.json")
    # package-lock.json (v2/v3) -> 정확한 버전
    if "packages" in data and isinstance(data["packages"], dict):
        res.source_format = "package-lock.json"
        for path, meta in data["packages"].items():
            if not path or not isinstance(meta, dict):
                continue
            name = path.split("node_modules/")[-1]
            version = meta.get("version")
            if name and version:
                res.components.append(Component("npm", name, version))
        return res.dedup()
    # package.json -> range 정리(추정)
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(sect) or {}).items():
            cleaned = _clean_npm_version(str(spec))
            if cleaned:
                ver, approx = cleaned
                res.components.append(Component("npm", name, ver, approximate=approx))
            else:
                res.skipped.append(f"{name} ({spec})")
    return res.dedup()


def _from_pom(text: str) -> ParseResult:
    res = ParseResult(source_format="pom.xml")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return res
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag[: root.tag.index("}") + 1]
    props = {}
    for p in root.findall(f".//{ns}properties/*"):
        props[p.tag.replace(ns, "")] = (p.text or "").strip()

    def resolve(v: str) -> Optional[str]:
        if not v:
            return None
        m = re.match(r"^\$\{(.+)\}$", v.strip())
        if m:
            return props.get(m.group(1))
        return v.strip()

    for dep in root.findall(f".//{ns}dependencies/{ns}dependency"):
        gid = dep.findtext(f"{ns}groupId", "").strip()
        aid = dep.findtext(f"{ns}artifactId", "").strip()
        ver = resolve(dep.findtext(f"{ns}version", "") or "")
        if gid and aid and ver:
            res.components.append(Component("Maven", f"{gid}:{aid}", ver))
        elif gid and aid:
            res.skipped.append(f"{gid}:{aid} (버전 미해결)")
    return res.dedup()


# --------------------------------------------------------------------------- #
# 진입점
# --------------------------------------------------------------------------- #
def parse(content: str, hint: str = "auto") -> ParseResult:
    """content 를 파싱해 Component 목록으로 정규화.

    hint: auto | cyclonedx | spdx | requirements | package_json | pom | purl
    """
    content = content.strip()
    hint = (hint or "auto").lower()

    if hint == "purl" or (hint == "auto" and content.startswith("pkg:")):
        res = ParseResult(source_format="purl-list")
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            c = parse_purl(line)
            if c:
                res.components.append(c)
            else:
                res.skipped.append(line)
        return res.dedup()

    # XML (pom)
    if hint == "pom" or (hint == "auto" and content.lstrip().startswith("<")):
        return _from_pom(content)

    # JSON 계열
    if content.startswith("{") or hint in ("cyclonedx", "spdx", "package_json"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON 파싱 실패: {e}")
        if hint == "cyclonedx" or "bomFormat" in data or data.get("components") is not None:
            return _from_cyclonedx(data)
        if hint == "spdx" or "spdxVersion" in data or data.get("packages") is not None and "SPDXID" in data:
            return _from_spdx(data)
        if hint == "package_json" or "dependencies" in data or "packages" in data:
            return _from_package_json(data)
        # SPDX packages fallback
        if data.get("packages") is not None:
            return _from_spdx(data)
        raise ValueError("알 수 없는 JSON 형식 (CycloneDX/SPDX/package.json 아님)")

    # requirements.txt
    return _from_requirements(content)
