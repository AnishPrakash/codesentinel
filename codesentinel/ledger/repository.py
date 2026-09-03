"""All ledger access. One module, so the 'no code is stored' guarantee is
auditable by reading a single file."""
from __future__ import annotations

import logging
from typing import Any

from ..models import ScanResult
from .store import connect

log = logging.getLogger(__name__)


def record_scan(result: ScanResult, model_used: bool = False) -> int | None:
    """Persist scan metadata. Returns the scan id, or None if not persisted.

    Note what is written below: path, language, counts, and per-finding
    rule_id / cwe / severity / line / confidence. No snippet, no explanation,
    no fix. That is the guarantee.
    """
    with connect() as conn:
        if conn is None:
            return None
        try:
            cur = conn.execute(
                "insert into scans (path, language, line_count, elapsed_ms, model_used)"
                " values (?, ?, ?, ?, ?)",
                (result.path, result.language.value, result.line_count,
                 round(result.elapsed_ms, 2), int(model_used)),
            )
            scan_id = cur.lastrowid
            if result.findings:
                conn.executemany(
                    "insert into findings (scan_id, rule_id, cwe, severity, line,"
                    " confidence) values (?, ?, ?, ?, ?, ?)",
                    [(scan_id, f.rule_id, f.cwe, int(f.severity), f.line,
                      float(f.confidence)) for f in result.findings],
                )
            return scan_id
        except Exception as exc:                              # noqa: BLE001
            log.warning("record_scan failed: %s", exc)
            return None


def record_attempt(rule_id: str, passed: bool) -> None:
    """Upsert the comprehension ledger. Records the outcome, never the answer."""
    with connect() as conn:
        if conn is None:
            return
        try:
            conn.execute(
                """
                insert into comprehension (rule_id, attempts, passes,
                                           first_passed_at, last_attempt_at)
                values (?, 1, ?, case when ? then datetime('now') end, datetime('now'))
                on conflict(rule_id) do update set
                    attempts        = attempts + 1,
                    passes          = passes + ?,
                    first_passed_at = coalesce(first_passed_at,
                                               case when ? then datetime('now') end),
                    last_attempt_at = datetime('now')
                """,
                (rule_id, int(passed), passed, int(passed), passed),
            )
        except Exception as exc:                              # noqa: BLE001
            log.warning("record_attempt failed: %s", exc)


def mastered_rules() -> set[str]:
    """Classes already explained correctly at least once. Used to stop
    re-gating someone on something they have demonstrated."""
    with connect() as conn:
        if conn is None:
            return set()
        try:
            rows = conn.execute(
                "select rule_id from comprehension where passes > 0").fetchall()
            return {r["rule_id"] for r in rows}
        except Exception as exc:                              # noqa: BLE001
            log.warning("mastered_rules failed: %s", exc)
            return set()


def progress() -> list[dict[str, Any]]:
    """The impact metric, measured by the product."""
    from ..rules.engine import DETERMINISTIC

    # Mastery is tracked over the deterministic classes only - advisories are
    # never gated, so there is nothing to demonstrate understanding of.
    by_rule: dict[str, dict] = {}
    with connect() as conn:
        if conn is not None:
            try:
                for r in conn.execute(
                        "select rule_id, attempts, passes, first_passed_at "
                        "from comprehension").fetchall():
                    by_rule[r["rule_id"]] = dict(r)
            except Exception as exc:                          # noqa: BLE001
                log.warning("progress failed: %s", exc)

    out = []
    for rid, name, cwe, _owasp, _tier in DETERMINISTIC:
        r = by_rule.get(rid, {})
        out.append({
            "rule_id": rid, "name": name, "cwe": cwe,
            "attempts": r.get("attempts", 0),
            "passes": r.get("passes", 0),
            "mastered": bool(r.get("passes", 0)),
            "first_passed_at": r.get("first_passed_at"),
        })
    return out


def history(limit: int = 20) -> list[dict[str, Any]]:
    with connect() as conn:
        if conn is None:
            return []
        try:
            rows = conn.execute(
                """
                select s.id, s.created_at, s.path, s.language, s.line_count,
                       s.elapsed_ms, count(f.id) as finding_count,
                       coalesce(max(f.severity), 0) as worst
                from scans s left join findings f on f.scan_id = s.id
                group by s.id
                order by s.created_at desc
                limit ?
                """, (limit,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:                              # noqa: BLE001
            log.warning("history failed: %s", exc)
            return []


def rule_frequency() -> list[dict[str, Any]]:
    """Which classes this user hits most - useful for the pitch and for them."""
    with connect() as conn:
        if conn is None:
            return []
        try:
            rows = conn.execute(
                "select rule_id, cwe, count(*) as hits from findings "
                "group by rule_id, cwe order by hits desc").fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:                              # noqa: BLE001
            log.warning("rule_frequency failed: %s", exc)
            return []


def reset() -> bool:
    """Wipe the ledger. `cs progress --reset`."""
    with connect() as conn:
        if conn is None:
            return False
        try:
            conn.executescript(
                "delete from findings; delete from scans; delete from comprehension;")
            return True
        except Exception as exc:                              # noqa: BLE001
            log.warning("reset failed: %s", exc)
            return False
