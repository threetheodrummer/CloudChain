from typing import List

from app.models import Finding
from app.sources import AWSDataSource

from .iam_scanner import IAMScanner
from .s3_scanner import S3Scanner
from .sg_scanner import SecurityGroupScanner


def run_all_scanners(source: AWSDataSource) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(S3Scanner(source).scan())
    findings.extend(IAMScanner(source).scan())
    findings.extend(SecurityGroupScanner(source).scan())
    return findings


__all__ = ["IAMScanner", "S3Scanner", "SecurityGroupScanner", "run_all_scanners"]
