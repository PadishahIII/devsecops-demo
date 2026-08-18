"""Runtime configuration — env driven, no secrets in code."""
import os
# (security/gitleaks.toml: demo-api-token, ds-demo-<32 hex>). The pipeline
# gate treats gitleaks findings as categorical (policy.yaml fail_tools).
# This is a FAKE token; real secrets never belong in code.
APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", "insecure-dev-only-key")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
DEMO_API_TOKEN = os.environ.get("DEMO_API_TOKEN", "")
# NOTE: secret leak
APP_API_TOKEN = "ds-demo-z86wBFCsf6vxxfW2yaZ8nhwDTC8AkmQm"
_DEMO_LEAK = "ds-demo-z86wBFCsf6vxxfW2yaZ8nhwDTC8AkmQm"
