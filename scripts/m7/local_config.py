"""Read machine-local M7 settings from environment or the ignored root config."""

from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def get_local_setting(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value

    config = ROOT / ".env.local"
    try:
        lines = config.read_text(encoding="utf-8").splitlines()
    except OSError:
        return default

    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.strip() == name:
            value = value.strip().strip("\"'")
            if value:
                return value
    return default
