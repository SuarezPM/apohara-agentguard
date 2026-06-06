//! Container / orchestrator destructive-command pack (OPT-IN, OFF by default).
//!
//! Per-leg rules for container tooling that destroys state in bulk:
//! `docker system prune -af`, `docker rm -f`, `kubectl delete --all`. Same
//! [`DestructiveRule`] shape as [`crate::gate::taxonomy::rules`] — no new
//! abstraction. Read-only inspection (`docker ps`, `kubectl get pods`) must NOT
//! match (see `benign_container.txt`).

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

fn m_docker_system_prune(s: &str) -> bool {
    // `docker system prune` (and `docker image/volume/network prune`) with `-a`
    // and/or `-f` reaps unused state; the `-af` form is the destructive one.
    re!(
        s,
        r"(?i)\bdocker\b\s+(system|image|volume|network|container)\s+prune\b[^|;&\n]*\s-[a-z]*[af]"
    )
}

fn m_docker_rm_force(s: &str) -> bool {
    // `docker rm -f` / `docker rmi -f` force-removes a running container/image;
    // also `docker container rm -f`.
    re!(
        s,
        r"(?i)\bdocker\b\s+(container\s+)?(rm|rmi)\b[^|;&\n]*\s-[a-z]*f"
    )
}

fn m_kubectl_delete_all(s: &str) -> bool {
    // `kubectl delete … --all` removes every object of a kind in a namespace.
    re!(s, r"(?i)\bkubectl\b\s+delete\b[^|;&\n]*\s--all\b")
}

/// All container-pack per-leg rules.
pub fn rules() -> &'static [DestructiveRule] {
    &[
        DestructiveRule {
            id: "docker-system-prune",
            severity: 8,
            category: "container",
            matcher: m_docker_system_prune,
        },
        DestructiveRule {
            id: "docker-rm-force",
            severity: 8,
            category: "container",
            matcher: m_docker_rm_force,
        },
        DestructiveRule {
            id: "kubectl-delete-all",
            severity: 9,
            category: "container",
            matcher: m_kubectl_delete_all,
        },
    ]
}
