#!/usr/bin/env python3
"""Test PostgreSQL connectivity using the DATABASE_URL environment variable."""

import os
import sys

import psycopg2
from psycopg2.extras import RealDictCursor

from env_config import load_local_env


TEMP_TABLE_NAME = "test_connection_probe"


load_local_env()


def configure_stdout() -> None:
    """Use UTF-8 when the runtime supports stream reconfiguration."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def require_database_url() -> str:
    """Read DATABASE_URL from the environment or raise a clear setup error."""
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url

    raise RuntimeError(
        "DATABASE_URL environment variable is required. "
        "Copy .env.example and set your local or Render PostgreSQL URL before running this script."
    )


def main() -> int:
    """Run a lightweight PostgreSQL connection probe."""
    configure_stdout()

    try:
        database_url = require_database_url()
        print("Testing PostgreSQL connection using DATABASE_URL...")

        with psycopg2.connect(database_url, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT version();")
                version = cursor.fetchone()
                print("[OK] Connection successful")
                print(f"PostgreSQL version: {version['version']}")

                cursor.execute(f"""
                    CREATE TEMP TABLE {TEMP_TABLE_NAME} (
                        id SERIAL PRIMARY KEY,
                        test_text TEXT NOT NULL
                    ) ON COMMIT DROP
                """)
                print("[OK] Temporary table creation successful")

                cursor.execute(
                    f"INSERT INTO {TEMP_TABLE_NAME} (test_text) VALUES (%s) RETURNING id",
                    ("Test connection",),
                )
                result = cursor.fetchone()
                print(f"[OK] Insert successful. ID: {result['id']}")

                cursor.execute(f"SELECT * FROM {TEMP_TABLE_NAME}")
                rows = cursor.fetchall()
                print(f"[OK] Select successful. Found {len(rows)} row(s)")

            conn.commit()

        print("[OK] Temporary table dropped automatically on commit")
        print("All tests passed. Database is ready to use.")
        return 0
    except Exception as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
