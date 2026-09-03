"""SQLite ledger. Schema, migrations, connection.

Deliberate omission: there is no column anywhere that can hold source code.
"""
from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from typing import Iterator

from ..config import get_settings

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

SCHEMA = """
create table if not exists meta (
    key   text primary key,
    value text not null
);

create table if not exists scans (
    id          integer primary key autoincrement,
    created_at  text    not null default (datetime('now')),
    path        text    not null,
    language    text    not null,
    line_count  integer not null,
    elapsed_ms  real    not null,
    model_used  integer not null default 0
);
create index if not exists scans_created_idx on scans (created_at desc);

create table if not exists findings (
    id         integer primary key autoincrement,
    scan_id    integer not null references scans(id) on delete cascade,
    rule_id    text    not null,
    cwe        text    not null,
    severity   integer not null,
    line       integer not null,
    confidence real    not null default 1.0
);
create index if not exists findings_scan_idx on findings (scan_id);
create index if not exists findings_rule_idx on findings (rule_id);

create table if not exists comprehension (
    rule_id         text primary key,
    attempts        integer not null default 0,
    passes          integer not null default 0,
    first_passed_at text,
    last_attempt_at text not null default (datetime('now'))
);
"""


@contextmanager
def connect() -> Iterator[sqlite3.Connection | None]:
    """Yields a connection, or None if the ledger cannot be opened.

    Every caller must handle None. A read-only filesystem, a corrupt file or a
    permissions problem must degrade the tool, never break a scan.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_settings().ledger_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("pragma foreign_keys = on")
        _migrate(conn)
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        log.warning("ledger unavailable: %s", exc)
        yield None
    finally:
        if conn is not None:
            conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    row = conn.execute("select value from meta where key = 'schema_version'").fetchone()
    if row is None:
        conn.execute("insert into meta (key, value) values ('schema_version', ?)",
                     (str(SCHEMA_VERSION),))
    elif int(row["value"]) != SCHEMA_VERSION:
        # Forward-only, and we are at version 1. If this ever trips, write a real
        # migration rather than silently dropping tables.
        log.warning("ledger schema version %s, expected %s",
                    row["value"], SCHEMA_VERSION)
