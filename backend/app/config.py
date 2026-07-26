"""
Central configuration for CloudChain.

Everything that varies between a real AWS scan and a demo-mode scan is
resolved here so the rest of the codebase (scanners, graph engine, risk
scoring) never has to know which mode it's running in.
"""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # "demo" runs entirely against seeded synthetic data (app/demo/mock_aws.py).
    # "real" talks to a live AWS account via boto3 using the caller's configured
    # credentials (env vars / ~/.aws/credentials / instance role).
    default_mode: str = os.environ.get("CLOUDCHAIN_MODE", "demo")

    # AWS region used for real-mode boto3 clients.
    aws_region: str = os.environ.get("AWS_REGION", "us-east-1")

    # Where scan snapshots are persisted for drift detection.
    db_path: str = os.environ.get(
        "CLOUDCHAIN_DB_PATH",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cloudchain.db"),
    )

    # Access keys / stale-credential threshold, in days.
    stale_key_age_days: int = int(os.environ.get("CLOUDCHAIN_STALE_KEY_DAYS", "90"))

    # Minimum password policy length CloudChain considers acceptable.
    min_password_length: int = int(os.environ.get("CLOUDCHAIN_MIN_PW_LEN", "14"))

    # Ports CloudChain treats as sensitive when exposed to 0.0.0.0/0.
    sensitive_ports: tuple = (22, 23, 21, 3389, 3306, 5432, 1433, 27017, 6379, 9200)


settings = Settings()
