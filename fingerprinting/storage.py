import json
import sqlite3
from datetime import datetime
from pathlib import Path


DATABASE_PATH = Path(
    "data/fingerprints.db"
)


def get_connection():
    """
    Open the local fingerprint database.

    The data directory is created automatically
    if it does not already exist.
    """

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Create the fingerprint table if needed.
    """

    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                fingerprint_hash TEXT UNIQUE NOT NULL,

                normalized_fingerprint TEXT NOT NULL,

                observation_count INTEGER NOT NULL DEFAULT 1,

                first_seen TEXT NOT NULL,

                last_seen TEXT NOT NULL,

                human_confirmed INTEGER NOT NULL DEFAULT 0,

                confirmed_category TEXT,

                confirmed_device_type TEXT,

                confirmed_os_family TEXT
            )
            """
        )

        connection.commit()

    finally:
        connection.close()


def save_fingerprint(
    fingerprint_hash,
    normalized_fingerprint
):
    """
    Save or update a normalized fingerprint.

    Existing fingerprint:
        increment observation_count
        update last_seen

    New fingerprint:
        create a new record
    """

    initialize_database()

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    serialized_fingerprint = json.dumps(
        normalized_fingerprint,
        sort_keys=True,
        separators=(",", ":")
    )

    connection = get_connection()

    try:
        existing = connection.execute(
            """
            SELECT id, observation_count
            FROM fingerprints
            WHERE fingerprint_hash = ?
            """,
            (
                fingerprint_hash,
            )
        ).fetchone()

        if existing:

            new_count = (
                existing["observation_count"]
                + 1
            )

            connection.execute(
                """
                UPDATE fingerprints
                SET
                    observation_count = ?,
                    last_seen = ?
                WHERE fingerprint_hash = ?
                """,
                (
                    new_count,
                    now,
                    fingerprint_hash
                )
            )

            connection.commit()

            return {
                "status": "updated",
                "observation_count": new_count
            }

        connection.execute(
            """
            INSERT INTO fingerprints (
                fingerprint_hash,
                normalized_fingerprint,
                observation_count,
                first_seen,
                last_seen,
                human_confirmed
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint_hash,
                serialized_fingerprint,
                1,
                now,
                now,
                0
            )
        )

        connection.commit()

        return {
            "status": "created",
            "observation_count": 1
        }

    finally:
        connection.close()
