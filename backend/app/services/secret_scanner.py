import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional

# File & Directory Filter Settings
EXCLUDED_DIRECTORIES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".idea",
    ".vscode", "dist", "build", ".pytest_cache", ".tox", "coverage", ".next"
}

EXCLUDED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip",
    ".tar", ".gz", ".7z", ".exe", ".dll", ".so", ".dylib", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".mov", ".avi", ".pyc",
    ".pyo", ".class", ".jar"
}

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB max per file


@dataclass
class SecretFindingItem:
    rule_id: str
    secret_type: str
    file_path: str
    line_number: int
    masked_snippet: str
    entropy_score: Optional[float]
    severity: str
    remediation_tip: str


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a string (bits per symbol)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def mask_secret(secret: str) -> str:
    """Obfuscate secret preserving small prefix and suffix for reference."""
    clean = secret.strip()
    length = len(clean)
    if length <= 6:
        return "*" * length
    if length <= 12:
        return clean[:2] + ("*" * (length - 4)) + clean[-2:]
    return clean[:4] + ("*" * (length - 8)) + clean[-4:]


def create_masked_snippet(line: str, secret: str) -> str:
    """Replace plain secret in line snippet with masked version."""
    masked = mask_secret(secret)
    return line.replace(secret, masked).strip()


# Regex Rules Definitions
RULES = [
    {
        "id": "AWS_ACCESS_KEY",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": "CRITICAL",
        "tip": "Revoca de inmediato esta clave de acceso en la consola de AWS IAM y rota las credenciales comprometidas."
    },
    {
        "id": "AWS_SECRET_KEY",
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]([0-9a-zA-Z/+]{40})['\"]"),
        "severity": "CRITICAL",
        "tip": "Revoca esta clave secreta de AWS inmediatamente en IAM y reemplázala por roles IAM temporales (STS) o variables de entorno en producción."
    },
    {
        "id": "GITHUB_PAT",
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36,255}|github_pat_[0-9a-zA-Z_]{82})\b"),
        "severity": "CRITICAL",
        "tip": "Invalida y elimina este Personal Access Token desde la configuración de tokens de GitHub (Settings -> Developer settings -> Personal access tokens)."
    },
    {
        "id": "GOOGLE_API_KEY",
        "name": "Google Cloud API Key",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,45})\b"),
        "severity": "HIGH",
        "tip": "Restringe y rota la API Key en Google Cloud Console (APIs & Services -> Credentials). Aplica restricciones de API y de IP/HTTP referer."
    },
    {
        "id": "SLACK_TOKEN",
        "name": "Slack Bot/User Token",
        "pattern": re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
        "severity": "CRITICAL",
        "tip": "Invalida este token de Slack inmediatamente desde la consola de tu aplicación en api.slack.com/apps."
    },
    {
        "id": "SLACK_WEBHOOK",
        "name": "Slack Incoming Webhook",
        "pattern": re.compile(r"(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]{8,12}\/B[0-9A-Za-z_]{8,12}\/[0-9A-Za-z_]{24})"),
        "severity": "HIGH",
        "tip": "Deshabilita el webhook entrante comprometido en la configuración de integraciones de tu espacio de trabajo de Slack."
    },
    {
        "id": "STRIPE_KEY",
        "name": "Stripe API Key",
        "pattern": re.compile(r"\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,34})\b"),
        "severity": "HIGH",
        "tip": "Rota la clave de Stripe desde el Stripe Dashboard -> Developers -> API keys."
    },
    {
        "id": "PRIVATE_KEY",
        "name": "Private Cryptographic Key",
        "pattern": re.compile(r"(-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----)"),
        "severity": "CRITICAL",
        "tip": "Esta clave privada criptográfica debe considerarse comprometida. Genera un nuevo par de llaves y revoca la anterior en todos los servidores autorizados."
    },
    {
        "id": "DATABASE_URI_PASSWORD",
        "name": "Database Connection Password",
        "pattern": re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_.-]+:([^@\s'\"]{3,})@[a-zA-Z0-9_.-]+"),
        "severity": "CRITICAL",
        "tip": "Cambia inmediatamente la contraseña de la base de datos y extrae la URI de conexión a variables de entorno protegidas."
    },
    {
        "id": "GENERIC_API_KEY_ASSIGNMENT",
        "name": "Generic Secret Assignment",
        "pattern": re.compile(r"(?i)(?:api_key|apikey|secret_key|secret|auth_token|access_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]"),
        "severity": "MEDIUM",
        "tip": "Almacena este secreto en variables de entorno o un gestor de secretos (Vault, AWS Secrets Manager) en lugar del código fuente."
    }
]

# Quoted assignment detector for entropy evaluation
QUOTED_ASSIGNMENT_REGEX = re.compile(r"[:=]\s*['\"]([^'\"\s]{16,128})['\"]")
ENTROPY_CANDIDATE_REGEX = re.compile(r"\b([a-zA-Z0-9+/=_-]{20,80})\b")
UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_COMMIT_REGEX = re.compile(r"^[0-9a-f]{40}$", re.I)


def scan_file_content(file_path: str, relative_path: str) -> List[SecretFindingItem]:
    """Analyze a single file for exposed secrets via RegEx and Shannon entropy."""
    findings: List[SecretFindingItem] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or len(line) > 2000:  # Skip empty or minified huge lines
            continue

        matched_spans = set()

        # 1. RegEx matching for known provider patterns
        for rule in RULES:
            for match in rule["pattern"].finditer(line):
                secret = match.group(1) if match.groups() else match.group(0)
                span = match.span()
                if span in matched_spans:
                    continue
                matched_spans.add(span)

                entropy = calculate_shannon_entropy(secret)
                severity = rule["severity"]
                if "pk_test" in secret or "sk_test" in secret:
                    severity = "LOW"

                findings.append(SecretFindingItem(
                    rule_id=rule["id"],
                    secret_type=rule["name"],
                    file_path=relative_path,
                    line_number=line_idx,
                    masked_snippet=create_masked_snippet(line, secret),
                    entropy_score=entropy,
                    severity=severity,
                    remediation_tip=rule["tip"]
                ))

        # 2. Shannon Entropy analysis for high-randomness secrets in assignments or tokens
        # Check quoted assignments (e.g. token = "...", password = "...")
        quoted_matches = list(QUOTED_ASSIGNMENT_REGEX.finditer(line))
        candidate_items = []
        for qm in quoted_matches:
            candidate_items.append((qm.group(1), qm.span(1)))

        # Also check word candidates if keyword is present on the line
        if any(kw in line.lower() for kw in ("key", "token", "secret", "pass", "cred", "auth", "pwd")):
            for em in ENTROPY_CANDIDATE_REGEX.finditer(line):
                candidate_items.append((em.group(1), em.span(1)))

        for candidate, span in candidate_items:
            if span in matched_spans:
                continue

            # Ignore UUIDs and Git commit hashes
            if UUID_REGEX.match(candidate) or HEX_COMMIT_REGEX.match(candidate):
                continue

            entropy = calculate_shannon_entropy(candidate)
            # High entropy threshold for generic secrets
            if entropy >= 4.1:
                matched_spans.add(span)
                findings.append(SecretFindingItem(
                    rule_id="SHANNON_HIGH_ENTROPY",
                    secret_type="High Entropy Generic Secret",
                    file_path=relative_path,
                    line_number=line_idx,
                    masked_snippet=create_masked_snippet(line, candidate),
                    entropy_score=entropy,
                    severity="MEDIUM",
                    remediation_tip="Se detectó una cadena de alta entropía que probablemente sea un token o credencial secreta. Verifica su propósito y muévela a variables de entorno."
                ))

    return findings


def scan_directory_for_secrets(base_dir: str) -> List[SecretFindingItem]:
    """Recursively walk directory and scan code files for secrets."""
    all_findings: List[SecretFindingItem] = []

    for root, dirs, files in os.walk(base_dir):
        # Exclude directories in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRECTORIES and not d.startswith(".")]

        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in EXCLUDED_EXTENSIONS:
                continue

            full_path = os.path.join(root, filename)

            # Check file size limit
            try:
                if os.path.getsize(full_path) > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            relative_path = os.path.relpath(full_path, base_dir).replace("\\", "/")
            file_findings = scan_file_content(full_path, relative_path)
            all_findings.extend(file_findings)

    return all_findings
