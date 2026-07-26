"""
S3 misconfiguration scanner.

Beyond the standard bucket-level checks every CSPM does (public access,
encryption, versioning), this scanner also does a content-aware pass: it
inspects object *keys* inside public buckets for credential-like naming
patterns (credentials.csv, .pem, .env, id_rsa, etc). That's what feeds the
attack-path graph engine a real entry point instead of a flat "bucket is
public" finding.
"""
from __future__ import annotations

import re
from typing import List

from app.models import Finding, Severity
from app.sources import AWSDataSource

CREDENTIAL_KEY_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [r"credential", r"secret", r"password", r"\.pem$", r"\.env$", r"id_rsa", r"\.key$", r"\.pfx$"]
]


def _matches_sensitive_pattern(key: str) -> bool:
    return any(p.search(key) for p in CREDENTIAL_KEY_PATTERNS)


class S3Scanner:
    resource_type = "s3_bucket"

    def __init__(self, source: AWSDataSource):
        self.source = source

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        for bucket in self.source.list_buckets():
            pab = self.source.get_public_access_block(bucket)
            fully_blocked = bool(pab) and all(pab.values())
            acl_public = self.source.is_bucket_acl_public(bucket)
            policy_public = self.source.is_bucket_policy_public(bucket)
            is_public = (not fully_blocked) and (acl_public or policy_public)

            if is_public:
                findings.append(
                    Finding(
                        resource_id=bucket,
                        resource_type=self.resource_type,
                        issue_code="S3_PUBLIC_ACCESS",
                        title=f"S3 bucket '{bucket}' is publicly accessible",
                        description=(
                            "Block Public Access is not fully enforced and the bucket ACL "
                            "or bucket policy grants access to Everyone/Authenticated Users."
                        ),
                        base_severity=Severity.HIGH,
                        internet_facing=True,
                        remediation=(
                            "Enable all four Block Public Access settings and remove public "
                            "grants from the bucket ACL/policy."
                        ),
                        evidence={
                            "public_access_block": pab,
                            "acl_public": acl_public,
                            "policy_public": policy_public,
                        },
                    )
                )

                object_keys = self.source.list_object_keys(bucket)
                matched = [k for k in object_keys if _matches_sensitive_pattern(k)]
                if matched:
                    leaked_for = self.source.leaked_credentials_hint(bucket)
                    findings.append(
                        Finding(
                            resource_id=bucket,
                            resource_type=self.resource_type,
                            issue_code="S3_SENSITIVE_OBJECT_EXPOSED",
                            title=f"Public bucket '{bucket}' contains credential-like object(s)",
                            description=(
                                "Object key(s) matching secret/credential naming patterns were "
                                f"found in a publicly accessible bucket: {matched}"
                            ),
                            base_severity=Severity.CRITICAL,
                            internet_facing=True,
                            sensitive=True,
                            remediation=(
                                "Rotate any credentials referenced by these objects immediately, "
                                "remove them from the bucket, and make the bucket private."
                            ),
                            evidence={"matched_keys": matched, "leaked_identity_hint": leaked_for},
                        )
                    )

            if not self.source.is_bucket_encrypted(bucket):
                findings.append(
                    Finding(
                        resource_id=bucket,
                        resource_type=self.resource_type,
                        issue_code="S3_NO_ENCRYPTION",
                        title=f"S3 bucket '{bucket}' has no default encryption",
                        description="Server-side encryption is not configured as the bucket default.",
                        base_severity=Severity.MEDIUM,
                        internet_facing=is_public,
                        remediation="Enable default server-side encryption (SSE-S3 or SSE-KMS).",
                    )
                )

            if not self.source.is_bucket_versioned(bucket):
                findings.append(
                    Finding(
                        resource_id=bucket,
                        resource_type=self.resource_type,
                        issue_code="S3_NO_VERSIONING",
                        title=f"S3 bucket '{bucket}' does not have versioning enabled",
                        description=(
                            "Without versioning, accidental deletes or ransomware-style "
                            "overwrites cannot be recovered."
                        ),
                        base_severity=Severity.LOW,
                        internet_facing=is_public,
                        remediation="Enable versioning on the bucket.",
                    )
                )

        return findings
