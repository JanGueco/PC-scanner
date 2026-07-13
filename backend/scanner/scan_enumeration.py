from __future__ import annotations

import os

# Tier A — highest risk
EXT_TIER_A = frozenset({".exe", ".dll", ".sys", ".drv", ".ocx"})

# Tier B — script-based threats
EXT_TIER_B = frozenset(
    {
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".scr",
        ".pif",
    }
)

# Tier C — other potentially malicious
EXT_TIER_C = frozenset(
    {
        ".msi",
        ".jar",
        ".com",
        ".cpl",
        ".inf",
        ".reg",
        ".lnk",
        ".url",
        ".iso",
        ".img",
    }
)

# Never scan — low value for name matching
SKIP_EXTENSIONS = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".webp",
        ".svg",
        ".mp3",
        ".mp4",
        ".wav",
        ".flac",
        ".aac",
        ".ogg",
        ".mkv",
        ".avi",
        ".mov",
        ".wmv",
        ".txt",
        ".log",
        ".md",
        ".csv",
        ".json",
        ".xml",
        ".html",
        ".pdf",
        ".docx",
        ".xlsx",
        ".pptx",
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
    }
)

SCANNABLE_EXTENSIONS = EXT_TIER_A | EXT_TIER_B | EXT_TIER_C

ALWAYS_SKIP_DIRS: tuple[str, ...] = (
    r"C:\Windows\WinSxS",
    r"C:\Windows\Installer",
    r"C:\Windows\SoftwareDistribution",
    r"C:\ProgramData\dbg",
    r"*\AppData\Local\Google\Chrome\User Data\Default\Cache",
    r"*\AppData\Local\Microsoft\Edge\User Data\Default\Cache",
    r"*\AppData\Local\Mozilla\Firefox\Profiles\*\cache2",
    r"*\AppData\Local\pip\cache",
    r"*\AppData\Local\npm-cache",
    r"*\node_modules",
    r"*\AppData\Local\conda",
    r"*\Anaconda3\pkgs",
    r"*\miniconda3\pkgs",
    r"*\steamapps\common",
    r"$Recycle.Bin",
    r"RECYCLER",
)


def _normalize_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _path_matches_skip_pattern(path: str, pattern: str) -> bool:
    path_norm = path.replace("/", "\\").lower()
    pattern_norm = pattern.replace("/", "\\").lower()

    if "*" not in pattern_norm:
        exact = pattern_norm.rstrip("\\")
        return path_norm == exact or path_norm.startswith(exact + "\\")

    segments = [segment for segment in pattern_norm.split("*") if segment]
    if not segments:
        return False

    position = 0
    for segment in segments:
        index = path_norm.find(segment, position)
        if index == -1:
            return False
        position = index + len(segment)
    return True


def should_skip_directory(dirpath: str) -> bool:
    normalized = _normalize_path(dirpath)
    for pattern in ALWAYS_SKIP_DIRS:
        if _path_matches_skip_pattern(normalized, pattern):
            return True
    return False


def extension_tier(file_path: str) -> int | None:
    """Return sort tier (0-3) or None if the file should be skipped entirely."""
    extension = os.path.splitext(file_path)[1].lower()
    if not extension:
        return 3
    if extension in SKIP_EXTENSIONS:
        return None
    if extension in EXT_TIER_A:
        return 0
    if extension in EXT_TIER_B:
        return 1
    if extension in EXT_TIER_C:
        return 2
    if extension in SCANNABLE_EXTENSIONS:
        return 3
    return 3


def is_scannable_extension(file_path: str) -> bool:
    return extension_tier(file_path) is not None


def high_priority_paths() -> list[str]:
    candidates = [
        os.environ.get("TEMP"),
        os.environ.get("TMP"),
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
        os.path.expandvars(r"%USERPROFILE%\Downloads"),
        os.path.expandvars(r"%APPDATA%"),
        os.path.expandvars(r"%LOCALAPPDATA%"),
        r"C:\Users\Public",
        r"C:\ProgramData",
    ]
    resolved: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        try:
            normalized = _normalize_path(os.path.abspath(candidate))
        except OSError:
            continue
        if normalized not in seen and os.path.isdir(normalized):
            seen.add(normalized)
            resolved.append(normalized)
    return resolved


def _is_under(path: str, root: str) -> bool:
    path_norm = _normalize_path(path)
    root_norm = _normalize_path(root)
    return path_norm == root_norm or path_norm.startswith(root_norm + os.sep)


def priority_roots_for_scan(scan_root: str) -> list[str]:
    root = _normalize_path(os.path.abspath(scan_root))
    priorities: list[str] = []
    for candidate in high_priority_paths():
        if _is_under(candidate, root):
            priorities.append(candidate)

    priorities.sort(key=len, reverse=True)
    deduped: list[str] = []
    for path in priorities:
        if any(_is_under(path, kept) for kept in deduped):
            continue
        deduped.append(path)
    return deduped


def _walk_directory(
    root: str,
    *,
    skip_subtrees: set[str],
    stats: dict[str, int],
) -> list[str]:
    files: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        if should_skip_directory(dirpath):
            stats["skipped_dirs"] += 1
            dirnames.clear()
            continue

        dirpath_norm = _normalize_path(dirpath)
        if any(_is_under(dirpath_norm, skip) for skip in skip_subtrees):
            dirnames.clear()
            continue

        pruned: list[str] = []
        for dirname in dirnames:
            child = os.path.join(dirpath, dirname)
            if os.path.islink(child):
                continue
            child_norm = _normalize_path(child)
            if should_skip_directory(child_norm):
                stats["skipped_dirs"] += 1
                continue
            if any(_is_under(child_norm, skip) for skip in skip_subtrees):
                continue
            pruned.append(dirname)
        dirnames[:] = pruned

        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            tier = extension_tier(full)
            if tier is None:
                stats["skipped_files"] += 1
                continue
            files.append(full)

    return files


def enumerate_scan_files(scan_root: str) -> tuple[list[str], dict[str, int]]:
    root = _normalize_path(os.path.abspath(scan_root))
    stats = {"skipped_dirs": 0, "skipped_files": 0}
    skip_subtrees: set[str] = set()
    ordered: list[str] = []
    seen: set[str] = set()

    def add_batch(paths: list[str]) -> None:
        for path in paths:
            normalized = _normalize_path(path)
            if normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(path)

    for priority_root in priority_roots_for_scan(root):
        add_batch(_sort_by_extension_tier(_walk_directory(priority_root, skip_subtrees=skip_subtrees, stats=stats)))
        skip_subtrees.add(priority_root)

    if root not in skip_subtrees:
        add_batch(_sort_by_extension_tier(_walk_directory(root, skip_subtrees=skip_subtrees, stats=stats)))

    return ordered, stats


def _sort_by_extension_tier(paths: list[str]) -> list[str]:
    buckets: dict[int, list[str]] = {0: [], 1: [], 2: [], 3: []}
    for path in paths:
        tier = extension_tier(path)
        if tier is not None:
            buckets[tier].append(path)
    ordered: list[str] = []
    for tier in (0, 1, 2, 3):
        ordered.extend(buckets[tier])
    return ordered


def iter_scan_batches(scan_root: str):
    """Yield priority directory batches first, then the scan-root remainder."""
    root = _normalize_path(os.path.abspath(scan_root))
    stats = {"skipped_dirs": 0, "skipped_files": 0}
    skip_subtrees: set[str] = set()

    for priority_root in priority_roots_for_scan(root):
        batch = _sort_by_extension_tier(
            _walk_directory(priority_root, skip_subtrees=skip_subtrees, stats=stats)
        )
        skip_subtrees.add(priority_root)
        yield batch, dict(stats), True

    if root not in skip_subtrees:
        batch = _sort_by_extension_tier(
            _walk_directory(root, skip_subtrees=skip_subtrees, stats=stats)
        )
        yield batch, dict(stats), False
