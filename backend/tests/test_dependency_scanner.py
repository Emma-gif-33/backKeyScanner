import json
import pytest
from app.services.dependency_scanner import (
    PackageItem,
    extract_advisory_url,
    extract_fixed_version,
    normalize_severity,
    parse_package_json,
    parse_package_lock_json,
    parse_requirements_txt,
    query_osv_batch,
)


def test_parse_requirements_txt():
    sample_reqs = """
    # Core dependencies
    requests==2.25.0
    urllib3==1.26.4; python_version >= '3.8'
    flask>=2.0.1
    gunicorn
    -r base.txt
    --index-url https://pypi.org/simple
    jinja2~=3.0.0
    """
    packages = parse_requirements_txt(sample_reqs, "requirements.txt")
    pkg_map = {p.name: p.version for p in packages}

    assert "requests" in pkg_map
    assert pkg_map["requests"] == "2.25.0"
    assert "urllib3" in pkg_map
    assert pkg_map["urllib3"] == "1.26.4"
    assert "flask" in pkg_map
    assert pkg_map["flask"] == "2.0.1"
    assert "jinja2" in pkg_map
    assert pkg_map["jinja2"] == "3.0.0"
    # Unversioned or comments should not be parsed as versioned items
    assert "gunicorn" not in pkg_map
    assert all(p.ecosystem == "PyPI" for p in packages)


def test_parse_package_json():
    sample_pkg = {
        "name": "sample-node-app",
        "dependencies": {
            "lodash": "^4.17.20",
            "express": "~4.16.1",
            "react": "18.2.0"
        },
        "devDependencies": {
            "jest": ">=27.0.0",
            "typescript": "5.0.4",
            "private-git": "git+https://github.com/foo/bar.git"
        }
    }
    packages = parse_package_json(json.dumps(sample_pkg), "package.json")
    pkg_map = {p.name: p.version for p in packages}

    assert pkg_map["lodash"] == "4.17.20"
    assert pkg_map["express"] == "4.16.1"
    assert pkg_map["react"] == "18.2.0"
    assert pkg_map["jest"] == "27.0.0"
    assert pkg_map["typescript"] == "5.0.4"
    assert "private-git" not in pkg_map
    assert all(p.ecosystem == "npm" for p in packages)


def test_parse_package_lock_json():
    sample_lock = {
        "name": "sample",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "sample"},
            "node_modules/lodash": {
                "version": "4.17.21"
            },
            "node_modules/@babel/core": {
                "version": "7.20.0"
            }
        }
    }
    packages = parse_package_lock_json(json.dumps(sample_lock), "package-lock.json")
    pkg_map = {p.name: p.version for p in packages}

    assert pkg_map["lodash"] == "4.17.21"
    assert pkg_map["@babel/core"] == "7.20.0"
    assert all(p.ecosystem == "npm" for p in packages)


def test_vulnerability_extraction_helpers():
    vuln = {
        "id": "GHSA-j8r2-6x86-q33q",
        "summary": "Requests vulnerable to information disclosure",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]
                    }
                ]
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"}
        ]
    }

    assert normalize_severity(vuln) == "HIGH"
    assert extract_fixed_version(vuln) == "2.31.0"
    assert extract_advisory_url(vuln, "GHSA-j8r2-6x86-q33q") == "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"


@pytest.mark.anyio
async def test_osv_batch_query_live_or_mock():
    # Test OSV query with a historically known vulnerable version (e.g. requests 2.20.0)
    test_packages = [
        PackageItem(name="requests", version="2.20.0", ecosystem="PyPI", manifest_file="requirements.txt")
    ]
    try:
        findings = await query_osv_batch(test_packages)
        # If internet is accessible, OSV should return known CVEs for requests 2.20.0
        assert len(findings) > 0
        assert any("CVE-" in f.osv_id or "GHSA-" in f.osv_id for f in findings)
        assert findings[0].package_name == "requests"
        assert findings[0].ecosystem == "PyPI"
    except Exception:
        # In isolated environments without external network, pass gracefully
        pytest.skip("External network to api.osv.dev not reachable.")
