from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from typing import Literal, TypedDict

SignatureStatus = Literal["valid", "invalid", "not_signed", "unverifiable"]


class SignatureResult(TypedDict):
    exe_path: str
    signature_valid: bool
    signer: str | None
    signed_by_microsoft: bool
    verification_error: str | None
    status: SignatureStatus


_cache: dict[str, SignatureResult] = {}
_cache_lock = threading.Lock()


def clear_signature_cache() -> None:
    with _cache_lock:
        _cache.clear()


def verify_signature(exe_path: str) -> SignatureResult:
    normalized = os.path.normcase(os.path.abspath(exe_path))
    with _cache_lock:
        cached = _cache.get(normalized)
        if cached is not None:
            return cached

    result = _verify_signature_uncached(exe_path)
    with _cache_lock:
        _cache[normalized] = result
    return result


def _verify_signature_uncached(exe_path: str) -> SignatureResult:
    base: SignatureResult = {
        "exe_path": exe_path,
        "signature_valid": False,
        "signer": None,
        "signed_by_microsoft": False,
        "verification_error": None,
        "status": "unverifiable",
    }

    if not os.path.isfile(exe_path):
        base["verification_error"] = "Executable file not found"
        return base

    ps_result = _verify_via_powershell(exe_path)
    if ps_result is not None:
        return ps_result

    wintrust_result = _verify_via_wintrust(exe_path)
    if wintrust_result is not None:
        return wintrust_result

    base["verification_error"] = (
        "Signature could not be verified — run Maat as Administrator to check this file"
    )
    return base


def _verify_via_powershell(exe_path: str) -> SignatureResult | None:
    escaped = exe_path.replace("'", "''")
    command = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{escaped}'; "
        "$s | Select-Object Status, SignerCertificate | ConvertTo-Json -Compress"
    )
    for args in (
        ["powershell", "-NoProfile", "-Command", command],
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
    ):
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue

        stdout = completed.stdout or ""
        if completed.returncode != 0 or not stdout.strip():
            continue

        try:
            payload = json.loads(stdout.strip())
        except json.JSONDecodeError:
            continue

        if isinstance(payload, list):
            payload = payload[0] if payload else {}

        return _parse_powershell_payload(exe_path, payload)

    return None


AUTHENTICODE_STATUS = {
    0: "Valid",
    1: "UnknownError",
    2: "NotSigned",
    4: "HashMismatch",
    8: "NotTrusted",
    16: "NotSupportedFileFormat",
}


def _normalize_authenticode_status(raw_status: object) -> str:
    if isinstance(raw_status, int):
        return AUTHENTICODE_STATUS.get(raw_status, str(raw_status))
    return str(raw_status or "")


def _parse_powershell_payload(exe_path: str, payload: dict) -> SignatureResult:
    raw_status = _normalize_authenticode_status(payload.get("Status"))
    certificate = payload.get("SignerCertificate")
    subject = ""
    if isinstance(certificate, dict):
        subject = str(certificate.get("Subject", "") or "")
        if not subject:
            subject_name = certificate.get("SubjectName")
            if isinstance(subject_name, dict):
                subject = str(subject_name.get("Name", "") or "")

    signer = _extract_signer_name(subject)
    signed_by_microsoft = _is_microsoft_signer(subject, signer)
    signature_valid = raw_status == "Valid"

    if raw_status == "Valid":
        status: SignatureStatus = "valid"
    elif raw_status == "NotSigned":
        status = "not_signed"
    elif raw_status:
        status = "invalid"
    else:
        status = "unverifiable"

    return {
        "exe_path": exe_path,
        "signature_valid": signature_valid,
        "signer": signer,
        "signed_by_microsoft": signed_by_microsoft,
        "verification_error": None,
        "status": status,
    }


def _extract_signer_name(subject: str) -> str | None:
    if not subject:
        return None
    match = re.search(r"CN=([^,]+)", subject, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return subject.strip() or None


def _is_microsoft_signer(subject: str, signer: str | None) -> bool:
    combined = f"{subject} {signer or ''}".lower()
    return (
        "cn=microsoft" in combined
        or "microsoft corporation" in combined
        or "microsoft windows" in combined
    )


def _verify_via_wintrust(exe_path: str) -> SignatureResult | None:
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None

    try:
        wintrust = ctypes.WinDLL("wintrust")
    except OSError:
        return None

    WVT_UI_NONE = 2
    WTD_REVOKE_NONE = 0
    WTD_CHOICE_FILE = 1
    WTD_STATEACTION_VERIFY = 1
    WTD_STATEACTION_CLOSE = 2
    TRUST_E_NOSIGNATURE = 0x800B0100
    TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", wintypes.BYTE * 8),
        ]

    action = GUID()
    action.Data1 = 0xAAC56BCD
    action.Data2 = 0x8445
    action.Data3 = 0x11D0
    action.Data4 = (ctypes.c_byte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)

    file_info = WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
        pcwszFilePath=exe_path,
        hFile=None,
        pgKnownSubject=None,
    )
    trust_data = WINTRUST_DATA(
        cbStruct=ctypes.sizeof(WINTRUST_DATA),
        pPolicyCallbackData=None,
        pSIPClientData=None,
        dwUIChoice=WVT_UI_NONE,
        fdwRevocationChecks=WTD_REVOKE_NONE,
        dwUnionChoice=WTD_CHOICE_FILE,
        pFile=ctypes.pointer(file_info),
        dwStateAction=WTD_STATEACTION_VERIFY,
        hWVTStateData=None,
        pwszURLReference=None,
        dwProvFlags=0,
        dwUIContext=0,
        pSignatureSettings=None,
    )

    try:
        result_code = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data))
    except OSError:
        return None
    finally:
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE
        try:
            wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data))
        except OSError:
            pass

    if result_code == 0:
        return {
            "exe_path": exe_path,
            "signature_valid": True,
            "signer": None,
            "signed_by_microsoft": False,
            "verification_error": None,
            "status": "valid",
        }

    if result_code in (TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN):
        status: SignatureStatus = "not_signed"
    else:
        status = "invalid"

    return {
        "exe_path": exe_path,
        "signature_valid": False,
        "signer": None,
        "signed_by_microsoft": False,
        "verification_error": None,
        "status": status,
    }


def is_system_directory_path(exe_path: str) -> bool:
    normalized = os.path.normpath(exe_path).lower()
    return "\\system32\\" in normalized or "\\syswow64\\" in normalized
