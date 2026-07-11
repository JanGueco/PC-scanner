from __future__ import annotations

import os
import winreg

from .models import StartupItem

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
HKCU_STARTUP = os.path.join(
    os.environ.get("APPDATA", ""),
    "Microsoft",
    "Windows",
    "Start Menu",
    "Programs",
    "Startup",
)
HKLM_STARTUP = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"


def _read_registry_run(hive: int, source: str) -> list[StartupItem]:
    items: list[StartupItem] = []
    try:
        with winreg.OpenKey(hive, RUN_KEY) as key:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                    items.append(
                        StartupItem(
                            name=name,
                            path=str(value),
                            source=source,  # type: ignore[arg-type]
                        )
                    )
                    index += 1
                except OSError:
                    break
    except OSError:
        pass
    return items


def _read_startup_folder(folder: str) -> list[StartupItem]:
    items: list[StartupItem] = []
    if not folder or not os.path.isdir(folder):
        return items
    try:
        for entry in os.listdir(folder):
            full = os.path.join(folder, entry)
            if os.path.isfile(full):
                items.append(
                    StartupItem(
                        name=entry,
                        path=full,
                        source="Startup Folder",
                    )
                )
    except OSError:
        pass
    return items


def list_startup_items() -> list[StartupItem]:
    items: list[StartupItem] = []
    items.extend(_read_registry_run(winreg.HKEY_CURRENT_USER, "Registry (HKCU)"))
    items.extend(_read_registry_run(winreg.HKEY_LOCAL_MACHINE, "Registry (HKLM)"))
    items.extend(_read_startup_folder(HKCU_STARTUP))
    items.extend(_read_startup_folder(HKLM_STARTUP))
    return items
