import os
import zipfile

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))

def create_samples():
    os.makedirs(SAMPLES_DIR, exist_ok=True)

    node_zip_path = os.path.join(SAMPLES_DIR, "demo_node_project.zip")
    with zipfile.ZipFile(node_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "package.json",
            """{
  "name": "demo-node-app",
  "version": "1.0.0",
  "description": "Sample vulnerable Node.js application for KeyScanner",
  "dependencies": {
    "lodash": "4.17.15",
    "axios": "0.21.1",
    "express": "4.16.1"
  }
}
"""
        )
        zf.writestr(
            ".env",
            """# Environment Credentials (VULNERABLE: Exposed in repo!)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DATABASE_URL=postgres://postgres:SuperSecretAdminPass123@prod-db.internal:5432/main_db
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T12345678/B12345678/123456789012345678901234
"""
        )
        zf.writestr(
            "src/index.js",
            """const axios = require('axios');
const lodash = require('lodash');

// Exposed Personal Access Token
const GITHUB_PAT = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";

console.log("App starting with token:", GITHUB_PAT);
"""
        )

    python_zip_path = os.path.join(SAMPLES_DIR, "demo_python_project.zip")
    with zipfile.ZipFile(python_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "requirements.txt",
            """# Known vulnerable dependencies for KeyScanner demo
requests==2.20.0
urllib3==1.24.1
jinja2==2.10.1
"""
        )
        zf.writestr(
            "config.py",
            """# Cloud and Third-Party API Keys (VULNERABLE)
GOOGLE_MAPS_KEY = "AIzaSyD12345678901234567890123456789"
STRIPE_LIVE_SECRET = "sk_live_51Abcdefghijklmnopqrstuvw"
AWS_ACCESS_KEY = "AKIA9876543210FEDCBA"

# Generic High-Entropy Token
API_SECRET_TOKEN = "zP9#mK2$vL5@8jR!1tY6bN4cF0wX3qA7"
"""
        )
        zf.writestr(
            "app.py",
            """import requests

def main():
    print("Demo Python service ready.")

if __name__ == "__main__":
    main()
"""
        )

    clean_zip_path = os.path.join(SAMPLES_DIR, "demo_clean_project.zip")
    with zipfile.ZipFile(clean_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "package.json",
            """{
  "name": "clean-modern-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.19.2"
  }
}
"""
        )
        zf.writestr(
            "index.js",
            """// Clean project using standard environment variable references
const port = process.env.PORT || 3000;
console.log(`Server starting on port ${port}`);
"""
        )

    print("Created sample zip archives:")
    print(" -", node_zip_path)
    print(" -", python_zip_path)
    print(" -", clean_zip_path)

if __name__ == "__main__":
    create_samples()
