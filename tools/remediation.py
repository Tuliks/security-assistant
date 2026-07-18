"""suggest_remediation — a local remediation-playbook lookup.

Deterministic knowledge tool: maps a finding category to a vetted set of fix
steps. Keeping it a lookup (not free LLM text) is the point — remediation advice
should be consistent and reviewable, and the model must call the tool rather than
improvise steps. Mirrors the labs' idiom: raise ModelRetry with the valid options
when the input doesn't match.
"""

from __future__ import annotations

from pydantic_ai import ModelRetry
from schemas import RemediationPlaybook

_PLAYBOOKS: dict[str, RemediationPlaybook] = {
    "exposed_secret": RemediationPlaybook(
        category="exposed_secret",
        steps=[
            "Revoke/rotate the leaked credential immediately at the provider.",
            "Purge the secret from git history (git filter-repo / BFG) and force-push.",
            "Move the secret to a secrets manager (Vault, AWS Secrets Manager) and inject at runtime.",
            "Add a pre-commit secret scanner (gitleaks) to block future commits.",
        ],
        references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
    ),
    "vulnerable_dependency": RemediationPlaybook(
        category="vulnerable_dependency",
        steps=[
            "Upgrade the package to the first fixed version listed in the advisory.",
            "Rebuild and re-scan the image to confirm the finding clears.",
            "Pin the fixed version and enable automated dependency updates (Dependabot/Renovate).",
            "If no fix exists yet, apply a mitigating control or remove the component.",
        ],
        references=["https://owasp.org/www-project-dependency-check/"],
    ),
    "sql_injection": RemediationPlaybook(
        category="sql_injection",
        steps=[
            "Replace string concatenation with parameterized queries / prepared statements.",
            "Validate and allowlist input types on the endpoint.",
            "Apply least-privilege DB credentials for the service.",
            "Add a regression test that submits an injection payload.",
        ],
        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    ),
    "misconfiguration": RemediationPlaybook(
        category="misconfiguration",
        steps=[
            "Change the setting to the hardened default (e.g. disable TLS 1.0/1.1, hide version banners).",
            "Codify the fix in IaC so it can't drift back.",
            "Re-scan to confirm and add the check to your baseline.",
        ],
        references=["https://owasp.org/www-project-secure-headers/"],
    ),
}


def suggest_remediation(category: str) -> RemediationPlaybook:
    """Return concrete remediation steps for a finding category.

    Args:
        category: The finding class, one of: exposed_secret, vulnerable_dependency,
            sql_injection, misconfiguration.
    """
    key = category.strip().lower()
    if key not in _PLAYBOOKS:
        raise ModelRetry(
            f"No playbook for {category!r}. Valid categories: {', '.join(sorted(_PLAYBOOKS))}."
        )
    return _PLAYBOOKS[key]
