import os
import shutil
import tempfile
import pytest
from app.services.secret_scanner import (
    calculate_shannon_entropy,
    mask_secret,
    scan_directory_for_secrets,
    scan_file_content,
)


def test_shannon_entropy_calculation():
    # Low entropy: repeated characters
    assert calculate_shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    assert calculate_shannon_entropy("abababababababab") == 1.0

    # High entropy: diverse character distribution
    high_entropy = calculate_shannon_entropy("W7x#9vQz!2mK$pL5@8jR^1tY&6bN*4cF")
    assert high_entropy > 4.5


def test_secret_masking():
    # Short secret
    assert mask_secret("12345") == "*****"

    # Medium secret
    masked_medium = mask_secret("1234567890")
    assert masked_medium.startswith("12")
    assert masked_medium.endswith("90")
    assert "*" in masked_medium

    # AWS Access Key style (20 chars)
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    masked = mask_secret(aws_key)
    assert masked == "AKIA************MPLE"
    assert "FODNN7EXA" not in masked


def test_known_patterns_detection():
    sample_content = """
    # Configuration File
    AWS_KEY = "AKIA1234567890ABCDEF"
    GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    GOOGLE_KEY = "AIzaSyD1234567890123456789012345678901"
    SLACK_BOT = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
    SLACK_HOOK = "https://hooks.slack.com/services/T12345678/B12345678/123456789012345678901234"
    DB_CONN = "postgresql://postgres:MySecretPassword123@localhost:5432/production_db"
    
    # Private Key
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y123...
    """

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".py", encoding="utf-8") as f:
        f.write(sample_content)
        temp_file = f.name

    try:
        findings = scan_file_content(temp_file, "sample_config.py")
        rule_ids = {f.rule_id for f in findings}

        assert "AWS_ACCESS_KEY" in rule_ids
        assert "GITHUB_PAT" in rule_ids
        assert "GOOGLE_API_KEY" in rule_ids
        assert "SLACK_TOKEN" in rule_ids
        assert "SLACK_WEBHOOK" in rule_ids
        assert "DATABASE_URI_PASSWORD" in rule_ids
        assert "PRIVATE_KEY" in rule_ids

        # Ensure no secret is stored in plain text in masked_snippet
        for finding in findings:
            assert finding.file_path == "sample_config.py"
            assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert finding.remediation_tip != ""
            assert "*" in finding.masked_snippet
            assert "AKIA1234567890ABCDEF" not in finding.masked_snippet
            assert "MySecretPassword123" not in finding.masked_snippet
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_shannon_entropy_generic_secret_detection():
    # Line containing generic token with high randomness
    content = 'api_secret_token = "zP9#mK2$vL5@8jR!1tY6bN4cF0wX3qA7"'
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".py", encoding="utf-8") as f:
        f.write(content)
        temp_file = f.name

    try:
        findings = scan_file_content(temp_file, "secrets.py")
        entropy_findings = [f for f in findings if f.entropy_score and f.entropy_score >= 4.3]
        assert len(entropy_findings) > 0
        assert entropy_findings[0].severity in ("MEDIUM", "HIGH")
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_directory_scan_and_exclusions():
    temp_dir = tempfile.mkdtemp()
    try:
        # 1. Normal source file with secret
        src_dir = os.path.join(temp_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "auth.py"), "w", encoding="utf-8") as f:
            f.write('aws_access = "AKIA9876543210FEDCBA"')

        # 2. Ignored directory: node_modules with fake secret
        node_modules = os.path.join(temp_dir, "node_modules", "pkg")
        os.makedirs(node_modules, exist_ok=True)
        with open(os.path.join(node_modules, "index.js"), "w", encoding="utf-8") as f:
            f.write('const key = "AKIA1111111111111111";')

        # 3. Ignored directory: .git
        git_dir = os.path.join(temp_dir, ".git")
        os.makedirs(git_dir, exist_ok=True)
        with open(os.path.join(git_dir, "config"), "w", encoding="utf-8") as f:
            f.write('token = "AKIA2222222222222222"')

        # 4. Ignored binary extension (.png)
        with open(os.path.join(src_dir, "logo.png"), "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\nAKIA3333333333333333")

        findings = scan_directory_for_secrets(temp_dir)

        # Only the secret in src/auth.py should be detected!
        assert len(findings) == 1
        assert findings[0].file_path == "src/auth.py"
        assert findings[0].rule_id == "AWS_ACCESS_KEY"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
