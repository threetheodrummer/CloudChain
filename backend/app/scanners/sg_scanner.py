"""
Security group scanner: flags ingress rules open to the internet
(0.0.0.0/0) on sensitive ports, with higher severity for database ports
and full port-range exposure.
"""
from __future__ import annotations

from typing import List

from app.config import settings
from app.models import Finding, Severity
from app.sources import AWSDataSource

DB_PORTS = {3306, 5432, 1433, 27017, 6379, 9200}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


class SecurityGroupScanner:
    resource_type = "security_group"

    def __init__(self, source: AWSDataSource):
        self.source = source

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        for sg in self.source.list_security_groups():
            for rule in sg.get("ingress", []):
                if rule.get("cidr") not in OPEN_CIDRS:
                    continue

                from_port = rule.get("from_port", 0)
                to_port = rule.get("to_port", 65535)
                full_range = from_port in (0, None) and to_port in (65535, None)
                touches_sensitive = full_range or any(
                    from_port <= p <= to_port for p in settings.sensitive_ports
                )
                if not touches_sensitive:
                    continue

                severity = Severity.CRITICAL if (full_range or any(
                    from_port <= p <= to_port for p in DB_PORTS
                )) else Severity.HIGH

                findings.append(
                    Finding(
                        resource_id=sg["group_id"],
                        resource_type=self.resource_type,
                        issue_code="SG_OPEN_TO_INTERNET",
                        title=f"Security group '{sg['name']}' allows internet access on port(s) {from_port}-{to_port}",
                        description=(
                            f"Ingress rule permits {rule.get('protocol', 'tcp').upper()} traffic from "
                            f"{rule.get('cidr')} on port(s) {from_port}-{to_port}."
                        ),
                        base_severity=severity,
                        internet_facing=True,
                        remediation="Restrict this rule to specific trusted CIDR ranges or remove it entirely.",
                        evidence={"group_name": sg["name"], "rule": rule},
                        dedupe_key=f"{rule.get('cidr')}:{from_port}-{to_port}:{rule.get('protocol','tcp')}",
                    )
                )

        return findings
