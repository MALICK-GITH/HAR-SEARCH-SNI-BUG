#!/usr/bin/env python3
"""Small helper to load local environment variables from a .env file."""

from pathlib import Path
import os


def load_local_env(env_filename: str = ".env") -> None:
    """Load a local .env file into os.environ without overriding existing values."""
    env_path = Path(__file__).resolve().parent / env_filename
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if value and len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        os.environ.setdefault(key, value)
