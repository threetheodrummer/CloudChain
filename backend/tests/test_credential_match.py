"""
Opt-in real-mode credential correlation.

Without a demo hint, the leaked-credentials edge can only be drawn by matching
an access key ID found in a public object to the IAM user that owns it. These
tests use the demo organisation with the hint switched off, so the only way
the internet-to-admin chain can appear is through that match.
"""
from app.pipeline import analyse_sources
from app.scanners.credential_match import extract_access_key_ids, mask_key_id
from app.scanners.s3_scanner import S3Scanner
from app.sources import DemoAWSDataSource

PROD = "111111111111"
REAL_LOOKING_ID = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key ID
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS's documented example secret

CSV = (
    "User name,Access key ID,Secret access key\n"
    f"svc-deploy-bot,{REAL_LOOKING_ID},{SECRET}\n"
).encode()


class NoHintSource(DemoAWSDataSource):
    """The demo org as a real account would look: no ground-truth hint."""

    def __init__(self, contents=CSV, other_account=None, **kw):
        super().__init__(account_id=PROD, **kw)
        self.contents = contents
        self.other_account = other_account
        self.reads = []

    def leaked_credentials_hint(self, bucket):
        return None

    def list_access_keys(self, user):
        keys = super().list_access_keys(user)
        if user == "svc-deploy-bot":
            keys = [dict(keys[0], id=REAL_LOOKING_ID)]
        return keys

    def read_object_head(self, bucket, key, max_bytes=65536):
        self.reads.append((bucket, key))
        return self.contents

    def access_key_account(self, access_key_id):
        return self.other_account


def _scan(source, inspect):
    source.inspect_credential_objects = inspect
    return analyse_sources([source], scan_id="t", mode="real")


def test_without_opt_in_nothing_is_read_and_no_chain_is_claimed():
    src = NoHintSource()
    result = _scan(src, inspect=False)
    assert src.reads == []
    assert result.attack_paths == []
    leak = next(f for f in result.findings if f.issue_code == "S3_SENSITIVE_OBJECT_EXPOSED")
    assert leak.evidence["leaked_identity_hint"] is None
    assert leak.evidence["leak_correlation"]["method"] == "not_inspected"


def test_with_opt_in_the_key_id_names_the_user_and_the_chain_appears():
    src = NoHintSource()
    result = _scan(src, inspect=True)
    assert src.reads, "credential-shaped objects should have been inspected"

    leak = next(f for f in result.findings if f.issue_code == "S3_SENSITIVE_OBJECT_EXPOSED")
    assert leak.evidence["leaked_identity_hint"] == "svc-deploy-bot"
    corr = leak.evidence["leak_correlation"]
    assert corr["method"] == "access_key_id_match"
    assert corr["matches"][0]["access_key_id"] == mask_key_id(REAL_LOOKING_ID)

    starts = {p.node_ids[0] for p in result.attack_paths}
    assert f"{PROD}/s3_bucket:public-uploads-bucket" in starts


def test_secret_never_reaches_the_findings_and_key_id_is_masked():
    result = _scan(NoHintSource(), inspect=True)
    # No finding anywhere carries the secret.
    assert SECRET not in repr([f.model_dump() for f in result.findings])
    # The leak finding carries only the masked ID. (The stale-key check names
    # key IDs from IAM metadata, which is existing, non-secret behaviour.)
    leak = next(f for f in result.findings if f.issue_code == "S3_SENSITIVE_OBJECT_EXPOSED")
    assert REAL_LOOKING_ID not in repr(leak.model_dump())


def test_only_public_buckets_are_inspected():
    src = NoHintSource()
    _scan(src, inspect=True)
    public = {b for b in src.list_buckets() if src.is_bucket_acl_public(b) or src.is_bucket_policy_public(b)}
    assert {b for b, _ in src.reads} <= public


def test_key_from_another_account_is_reported_not_guessed():
    other = b"AKIAZZZZZZZZZZZZZZZZ\n"
    src = NoHintSource(contents=other, other_account="999999999999")
    result = _scan(src, inspect=True)
    leak = next(f for f in result.findings if f.issue_code == "S3_SENSITIVE_OBJECT_EXPOSED")
    assert leak.evidence["leaked_identity_hint"] is None
    un = leak.evidence["leak_correlation"]["unattributed"]
    assert un and un[0]["owner_account"] == "999999999999"
    assert result.attack_paths == []


def test_temporary_keys_are_flagged_as_unattributable():
    src = NoHintSource(contents=b"aws_access_key_id = ASIAABCDEFGHIJKLMNOP\n")
    result = _scan(src, inspect=True)
    leak = next(f for f in result.findings if f.issue_code == "S3_SENSITIVE_OBJECT_EXPOSED")
    assert "temporary" in leak.evidence["leak_correlation"]["unattributed"][0]["reason"]


def test_demo_mode_still_uses_ground_truth_and_reads_nothing():
    class Spy(DemoAWSDataSource):
        reads = []

        def read_object_head(self, *a, **k):
            Spy.reads.append(a)
            return None

    findings = S3Scanner(Spy(account_id=PROD), inspect_credential_objects=True).scan()
    leak = next(f for f in findings if f.issue_code == "S3_SENSITIVE_OBJECT_EXPOSED")
    assert leak.evidence["leak_correlation"]["method"] == "demo_ground_truth"
    assert Spy.reads == []


def test_key_id_extraction():
    blob = (
        b"id=AKIAIOSFODNN7EXAMPLE x=XAKIAIOSFODNN7EXAMPLE "
        b"AKIAIOSFODNN7EXAMPLE ASIAABCDEFGHIJKLMNOP AKIASHORT"
    )
    assert extract_access_key_ids(blob) == ["AKIAIOSFODNN7EXAMPLE", "ASIAABCDEFGHIJKLMNOP"]
    assert extract_access_key_ids(b"") == []
    assert mask_key_id("AKIAIOSFODNN7EXAMPLE") == "AKIA****MPLE"
