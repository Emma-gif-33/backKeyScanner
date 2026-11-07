import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional
import httpx

OSV_BATCH_QUERY_URL = "https://api.osv.dev/v1/querybatch"

# Manifest filenames recognized
REQUIREMENTS_FILES = {"requirements.txt", "requirements-dev.txt", "requirements_prod.txt", "deps.txt"}
PACKAGE_JSON = "package.json"
PACKAGE_LOCK_JSON = "package-lock.json"

EXCLUDED_DIRECTORIES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".idea",
    ".vscode", "dist", "build", ".pytest_cache", ".tox", "coverage"
}


@dataclass
class PackageItem:
    name: str
    version: str
    ecosystem: str       # "PyPI" | "npm"
    manifest_file: str   # Relative path in workspace


@dataclass
class DependencyFindingItem:
    package_name: str
    installed_version: str
    ecosystem: str
    manifest_file: str
    osv_id: str
    severity: str
    fixed_version: Optional[str]
    summary: Optional[str]
    advisory_url: Optional[str]


def parse_requirements_txt(content: str, manifest_path: str) -> List[PackageItem]:
    """Parse Python requirements.txt lines into PackageItem instances."""
    packages: List[PackageItem] = []
    # Pattern to match package name and version (e.g. requests==2.25.0, flask>=2.0.0, etc.)
    req_pattern = re.compile(
        r"^\s*([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|>|<|=)?\s*([0-9a-zA-Z\.\-_+]+)?"
    )

    for raw_line in content.splitlines():
        line = raw_line.strip()
        # Skip empty lines, comments, or pip options (-r, -i, etc.)
        if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
            continue

        # Strip environment markers (e.g. ; python_version >= '3.8')
        line = line.split(";")[0].strip()

        match = req_pattern.match(line)
        if match:
            pkg_name = match.group(1).strip()
            version = match.group(2).strip() if match.group(2) else ""

            # Only query OSV if an exact or base version is specified
            if version:
                packages.append(PackageItem(
                    name=pkg_name,
                    version=version,
                    ecosystem="PyPI",
                    manifest_file=manifest_path
                ))

    return packages


def parse_package_json(content: str, manifest_path: str) -> List[PackageItem]:
    """Parse Node.js package.json dependencies and devDependencies."""
    packages: List[PackageItem] = []
    try:
        data = json.loads(content)
    except Exception:
        return packages

    all_deps: Dict[str, str] = {}
    if isinstance(data.get("dependencies"), dict):
        all_deps.update(data["dependencies"])
    if isinstance(data.get("devDependencies"), dict):
        all_deps.update(data["devDependencies"])

    for name, raw_version in all_deps.items():
        if not isinstance(raw_version, str):
            continue
        # Clean semver operators (^, ~, >=, <=, =, v)
        clean_version = re.sub(r"^[\^~>=<v=]+", "", raw_version.strip())
        # Skip urls, git hashes, or wildcard versions
        if not clean_version or clean_version == "*" or "/" in clean_version or ":" in clean_version:
            continue

        packages.append(PackageItem(
            name=name,
            version=clean_version,
            ecosystem="npm",
            manifest_file=manifest_path
        ))

    return packages


def parse_package_lock_json(content: str, manifest_path: str) -> List[PackageItem]:
    """Parse exact resolved versions from package-lock.json (v1, v2, v3)."""
    packages: List[PackageItem] = []
    try:
        data = json.loads(content)
    except Exception:
        return packages

    # Lockfile v2 / v3 packages mapping
    if "packages" in data and isinstance(data["packages"], dict):
        for pkg_key, pkg_info in data["packages"].items():
            if not pkg_key or not isinstance(pkg_info, dict):
                continue
            # package keys typically look like "node_modules/lodash" or "node_modules/@babel/core"
            if "node_modules/" in pkg_key:
                name = pkg_key.split("node_modules/")[-1]
            else:
                name = pkg_key

            version = pkg_info.get("version")
            if name and version:
                packages.append(PackageItem(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    manifest_file=manifest_path
                ))
    # Lockfile v1 dependencies mapping
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        for name, pkg_info in data["dependencies"].items():
            if isinstance(pkg_info, dict) and "version" in pkg_info:
                packages.append(PackageItem(
                    name=name,
                    version=pkg_info["version"],
                    ecosystem="npm",
                    manifest_file=manifest_path
                ))

    return packages


def find_manifest_packages(base_dir: str) -> List[PackageItem]:
    """Find all supported package manifests in workspace and parse them."""
    collected_packages: List[PackageItem] = []

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRECTORIES and not d.startswith(".")]

        has_lock = PACKAGE_LOCK_JSON in files
        for filename in files:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, base_dir).replace("\\", "/")

            try:
                if filename in REQUIREMENTS_FILES or filename.endswith(".requirements.txt"):
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        collected_packages.extend(parse_requirements_txt(f.read(), rel_path))

                elif filename == PACKAGE_LOCK_JSON:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        collected_packages.extend(parse_package_lock_json(f.read(), rel_path))

                elif filename == PACKAGE_JSON and not has_lock:
                    # Prefer package-lock.json if available; else fallback to package.json
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        collected_packages.extend(parse_package_json(f.read(), rel_path))
            except Exception:
                continue

    # Deduplicate packages by (name, version, ecosystem)
    seen = set()
    unique_packages: List[PackageItem] = []
    for p in collected_packages:
        key = (p.name.lower(), p.version, p.ecosystem)
        if key not in seen:
            seen.add(key)
            unique_packages.append(p)

    return unique_packages


def normalize_severity(vuln_data: dict) -> str:
    """Extract and normalize CVSS or database specific severity to CRITICAL|HIGH|MEDIUM|LOW."""
    db_specific = vuln_data.get("database_specific") or {}
    sev_raw = db_specific.get("severity") or ""

    if isinstance(sev_raw, str) and sev_raw:
        sev_upper = sev_raw.upper()
        if "CRIT" in sev_upper:
            return "CRITICAL"
        if "HIGH" in sev_upper:
            return "HIGH"
        if "MODERATE" in sev_upper or "MED" in sev_upper:
            return "MEDIUM"
        if "LOW" in sev_upper:
            return "LOW"

    # Check for CVSS v3 score in severity array
    severities = vuln_data.get("severity") or []
    if isinstance(severities, list):
        for item in severities:
            score_str = item.get("score", "")
            # Example CVSS string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
            if "CVSS" in score_str:
                # If score vector is provided, check high-impact vectors
                if "/C:H/I:H/A:H" in score_str or "/C:H/I:H" in score_str:
                    return "CRITICAL"
                elif "/C:H" in score_str or "/I:H" in score_str or "/A:H" in score_str:
                    return "HIGH"
                else:
                    return "MEDIUM"

    return "MEDIUM"


def extract_fixed_version(vuln_data: dict) -> Optional[str]:
    """Find the recommended fixed version from affected ranges events."""
    for affected in vuln_data.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return None


def extract_advisory_url(vuln_data: dict, osv_id: str) -> str:
    """Find primary advisory link or fallback to OSV website."""
    for ref in vuln_data.get("references", []):
        ref_type = ref.get("type", "").upper()
        if ref_type in ("ADVISORY", "WEB"):
            return ref.get("url", "")
    return f"https://osv.dev/vulnerability/{osv_id}"


async def query_osv_batch(packages: List[PackageItem]) -> List[DependencyFindingItem]:
    """Query OSV.dev batch API for multiple packages concurrently."""
    if not packages:
        return []

    findings: List[DependencyFindingItem] = []
    # OSV batch query limit is up to 1000 items per request, chunk in batches of 200
    chunk_size = 200

    async with httpx.AsyncClient(timeout=20.0) as client:
        for i in range(0, len(packages), chunk_size):
            chunk = packages[i:i + chunk_size]
            payload = {
                "queries": [
                    {
                        "package": {
                            "name": pkg.name,
                            "ecosystem": pkg.ecosystem
                        },
                        "version": pkg.version
                    }
                    for pkg in chunk
                ]
            }

            try:
                response = await client.post(OSV_BATCH_QUERY_URL, json=payload)
                if response.status_code != 200:
                    continue

                data = response.json()
                results = data.get("results", [])

                for pkg_idx, result in enumerate(results):
                    if pkg_idx >= len(chunk):
                        break

                    current_pkg = chunk[pkg_idx]
                    vulns = result.get("vulns", [])

                    for vuln in vulns:
                        osv_id = vuln.get("id") or "UNKNOWN_VULN"
                        # If aliases contain a CVE (e.g. CVE-2023-xxxx), pick it for readability if desired
                        aliases = vuln.get("aliases", [])
                        cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)

                        severity = normalize_severity(vuln)
                        fixed_ver = extract_fixed_version(vuln)
                        summary = vuln.get("summary") or (vuln.get("details", "")[:180] + "..." if vuln.get("details") else "Known security vulnerability.")
                        advisory_url = extract_advisory_url(vuln, osv_id)

                        findings.append(DependencyFindingItem(
                            package_name=current_pkg.name,
                            installed_version=current_pkg.version,
                            ecosystem=current_pkg.ecosystem,
                            manifest_file=current_pkg.manifest_file,
                            osv_id=cve_id,
                            severity=severity,
                            fixed_version=fixed_ver,
                            summary=summary,
                            advisory_url=advisory_url
                        ))
            except Exception:
                # Network or OSV timeout failure: log or gracefully proceed
                continue

    return findings


async def scan_directory_for_vulnerabilities(base_dir: str) -> List[DependencyFindingItem]:
    """Scan workspace directory, detect manifests, and query OSV.dev for CVEs."""
    packages = find_manifest_packages(base_dir)
    if not packages:
        return []
    return await query_osv_batch(packages)
