"""
Real-mode credential correlation: whose key is in that public file?

In demo mode the leaked-credentials edge comes from a ground-truth hint. On a
real account there is no hint, so the edge was never drawn and an
internet-to-admin chain could not be found outside the demo. This module
closes that gap, opt-in only.

How it works:
  1. The S3 scanner has already found credential-shaped object names in a
     PUBLIC bucket.
  2. For each of those objects (capped), read the first few KB.
  3. Pull out anything shaped like an AWS access key ID (AKIA... / ASIA...).
  4. Match each ID against iam:ListAccessKeys for every user in the account.
  5. If one matches, that user is the leaked identity, and the edge is drawn.

What it never does:
  - use a key. Secret keys are not even extracted; the regex only looks for
    key IDs, and the object bytes are dropped as soon as the IDs are pulled.
  - log, persist or return object contents. Only masked key IDs
    (AKIA****WXYZ) and the matching user name reach the finding.
  - run unless the operator asked for it (CLOUDCHAIN_INSPECT_CREDENTIAL_OBJECTS
    or the CLI's --inspect-credential-objects).

ASIA keys are temporary STS credentials. They don't appear in ListAccessKeys,
so they are reported as found-but-unattributable rather than guessed at.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.sources import AWSDataSource

# 20 characters: a 4-letter prefix and 16 base32-ish characters. The
# look-arounds stop the pattern matching inside a longer token.
ACCESS_KEY_ID_RE = re.compile(rb"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])")

MAX_OBJECTS_PER_BUCKET = 20
MAX_BYTES_PER_OBJECT = 64 * 1024


def extract_access_key_ids(blob: bytes) -> List[str]:
    """Access key IDs found in a blob, in first-seen order, without duplicates."""
    seen: List[str] = []
    for match in ACCESS_KEY_ID_RE.finditer(blob or b""):
        key_id = match.group(1).decode("ascii")
        if key_id not in seen:
            seen.append(key_id)
    return seen


def mask_key_id(key_id: str) -> str:
    """AKIA****WXYZ. Key IDs aren't secret, but there's no reason to print one whole."""
    return f"{key_id[:4]}****{key_id[-4:]}" if len(key_id) >= 8 else "****"


class KeyOwnerIndex:
    """Maps access key ID -> (user, status) for one account. Built lazily, once."""

    def __init__(self, source: AWSDataSource):
        self._source = source
        self._index: Optional[Dict[str, Dict[str, str]]] = None

    def lookup(self, key_id: str) -> Optional[Dict[str, str]]:
        if self._index is None:
            self._index = {}
            for user in self._source.list_iam_users():
                for key in self._source.list_access_keys(user):
                    if key.get("id"):
                        self._index[key["id"]] = {"user": user, "status": key.get("status", "")}
        return self._index.get(key_id)


def correlate_leaked_credentials(
    source: AWSDataSource,
    bucket: str,
    object_keys: List[str],
    index: KeyOwnerIndex,
) -> Dict[str, Any]:
    """Try to name the IAM user whose credentials a public object leaks.

    Returns {"user": Optional[str], "method": "access_key_id_match",
    "objects_inspected": int, "matches": [...], "unattributed": [...]}.
    "user" is the first in-account match; every match is listed in evidence so
    a bucket leaking several users' keys isn't summarised as one.
    """
    matches: List[Dict[str, Any]] = []
    unattributed: List[Dict[str, Any]] = []
    inspected = 0

    for key in object_keys[:MAX_OBJECTS_PER_BUCKET]:
        blob = source.read_object_head(bucket, key, MAX_BYTES_PER_OBJECT)
        if blob is None:
            continue
        inspected += 1
        key_ids = extract_access_key_ids(blob)
        # Drop the bytes immediately: only the IDs go any further.
        del blob

        for key_id in key_ids:
            owner = index.lookup(key_id)
            if owner:
                matches.append(
                    {
                        "object": key,
                        "access_key_id": mask_key_id(key_id),
                        "user": owner["user"],
                        "key_status": owner["status"],
                    }
                )
                continue
            entry: Dict[str, Any] = {"object": key, "access_key_id": mask_key_id(key_id)}
            if key_id.startswith("ASIA"):
                entry["reason"] = "temporary STS credential; not listed by iam:ListAccessKeys"
            else:
                owner_account = source.access_key_account(key_id)
                if owner_account and owner_account != source.account_id:
                    entry["reason"] = f"belongs to account {owner_account}, outside this scan"
                    entry["owner_account"] = owner_account
                else:
                    entry["reason"] = "no IAM user in this account owns this key (deleted, or not visible)"
            unattributed.append(entry)

    # Prefer a match whose key is still active: that is the one an attacker can use.
    active = [m for m in matches if str(m["key_status"]).lower() == "active"]
    chosen = (active or matches or [None])[0]

    return {
        "user": chosen["user"] if chosen else None,
        "method": "access_key_id_match",
        "objects_inspected": inspected,
        "matches": matches,
        "unattributed": unattributed,
    }
