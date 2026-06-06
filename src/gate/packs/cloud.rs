//! Cloud-provider destructive-command pack (OPT-IN, OFF by default).
//!
//! Per-leg rules for cloud CLIs whose subcommands tear down remote resources:
//! `aws s3 rb --force`, `aws … delete-*`, `gcloud … delete`, `az … delete`.
//! Same [`DestructiveRule`] shape as [`crate::gate::taxonomy::rules`] — no new
//! abstraction. Patterns are scoped to look-alike-safe: a bare `aws s3 ls` or
//! `gcloud … describe` must NOT match (see `benign_cloud.txt`).

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

fn m_aws_s3_rb_force(s: &str) -> bool {
    // `aws s3 rb …` removes a bucket; `--force` empties+removes it non-empty.
    re!(s, r"(?i)\baws\b\s+s3\b\s+rb\b[^|;&\n]*\s--force\b")
}

fn m_aws_delete(s: &str) -> bool {
    // Any `aws <service> delete-*` API call (delete-bucket, delete-stack,
    // delete-db-instance, delete-table, terminate-instances, …).
    re!(
        s,
        r"(?i)\baws\b[^|;&\n]*\s(delete-\w+|terminate-instances)\b"
    )
}

fn m_gcloud_delete(s: &str) -> bool {
    // `gcloud <group> … delete` removes a GCP resource.
    re!(s, r"(?i)\bgcloud\b[^|;&\n]*\sdelete\b")
}

fn m_az_delete(s: &str) -> bool {
    // `az <group> … delete` removes an Azure resource.
    re!(s, r"(?i)\baz\b[^|;&\n]*\sdelete\b")
}

/// All cloud-pack per-leg rules.
pub fn rules() -> &'static [DestructiveRule] {
    &[
        DestructiveRule {
            id: "aws-s3-rb-force",
            severity: 9,
            category: "cloud",
            matcher: m_aws_s3_rb_force,
        },
        DestructiveRule {
            id: "aws-delete",
            severity: 8,
            category: "cloud",
            matcher: m_aws_delete,
        },
        DestructiveRule {
            id: "gcloud-delete",
            severity: 8,
            category: "cloud",
            matcher: m_gcloud_delete,
        },
        DestructiveRule {
            id: "az-delete",
            severity: 8,
            category: "cloud",
            matcher: m_az_delete,
        },
    ]
}
