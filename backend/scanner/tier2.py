from __future__ import annotations

import hashlib
from pathlib import Path

import httpx

MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
CIRCL_API_URL = "https://hashlookup.circl.lu/lookup/sha256/"
API_TIMEOUT = 5.0


def compute_sha256(file_path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def check_malwarebazaar_hash(client: httpx.Client, sha256: str, auth_key: str) -> bool:
    if not auth_key:
        return False
    try:
        response = client.post(
            MB_API_URL,
            data={"query": "get_info", "hash": sha256},
            headers={"Auth-Key": auth_key},
            timeout=API_TIMEOUT,
        )
        if response.status_code != 200:
            return False
        payload = response.json()
        return payload.get("query_status") == "ok"
    except (httpx.HTTPError, ValueError):
        return False


def check_circl_hash(client: httpx.Client, sha256: str) -> bool:
    try:
        response = client.get(
            f"{CIRCL_API_URL}{sha256.lower()}",
            headers={"accept": "application/json"},
            timeout=API_TIMEOUT,
        )
        if response.status_code != 200:
            return False
        payload = response.json()
        return bool(payload)
    except (httpx.HTTPError, ValueError):
        return False


class Tier2Verifier:
    def __init__(self, auth_key: str) -> None:
        self.auth_key = auth_key
        self._client = httpx.Client()

    def close(self) -> None:
        self._client.close()

    def verify(self, file_path: str) -> tuple[str, str | None, str | None, str | None]:
        """
        Returns (status, match_type, sha256, database)
        status: clean | suspicious | malicious
        """
        sha256 = compute_sha256(file_path)
        if not sha256:
            return "clean", "name", None, None

        if check_malwarebazaar_hash(self._client, sha256, self.auth_key):
            return "malicious", "sha256", sha256, "MalwareBazaar"

        if check_circl_hash(self._client, sha256):
            return "clean", "name", sha256, "CIRCL"

        return "suspicious", "name", sha256, None
