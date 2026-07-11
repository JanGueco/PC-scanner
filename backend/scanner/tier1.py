from __future__ import annotations

import os


def check_filename(filename: str, name_set: set[str]) -> bool:
    basename = os.path.basename(filename).lower()
    return basename in name_set
