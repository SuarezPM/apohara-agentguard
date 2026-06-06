//! Database DDL destructive-command pack (OPT-IN, OFF by default).
//!
//! Per-leg rules for SQL DDL that destroys schema or data: `DROP TABLE`,
//! `DROP DATABASE`, `TRUNCATE`. Same [`DestructiveRule`] shape as
//! [`crate::gate::taxonomy::rules`] — no new abstraction. A read-only
//! `SELECT … FROM t` must NOT match (see `benign_db.txt`).

use std::sync::OnceLock;

use regex::Regex;

use crate::gate::taxonomy::DestructiveRule;

macro_rules! re {
    ($name:ident, $pat:expr) => {{
        static CELL: OnceLock<Regex> = OnceLock::new();
        CELL.get_or_init(|| Regex::new($pat).expect(concat!("valid regex: ", $pat)))
            .is_match($name)
    }};
}

fn m_drop_table(s: &str) -> bool {
    // `DROP TABLE [IF EXISTS] name` — tolerate the optional `IF EXISTS` clause.
    re!(s, r"(?i)\bdrop\s+table\b")
}

fn m_drop_database(s: &str) -> bool {
    // `DROP DATABASE` / `DROP SCHEMA` — both tear down a whole database.
    re!(s, r"(?i)\bdrop\s+(database|schema)\b")
}

fn m_truncate(s: &str) -> bool {
    // `TRUNCATE [TABLE] name` empties a table irreversibly.
    re!(s, r"(?i)\btruncate\s+(table\b|\w)")
}

/// All db-pack per-leg rules.
pub fn rules() -> &'static [DestructiveRule] {
    &[
        DestructiveRule {
            id: "drop-table",
            severity: 8,
            category: "db",
            matcher: m_drop_table,
        },
        DestructiveRule {
            id: "drop-database",
            severity: 9,
            category: "db",
            matcher: m_drop_database,
        },
        DestructiveRule {
            id: "truncate",
            severity: 8,
            category: "db",
            matcher: m_truncate,
        },
    ]
}
