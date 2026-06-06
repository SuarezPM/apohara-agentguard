//! Opt-in domain packs: extra destructive-command rules grouped by domain
//! (cloud, db, container), OFF by default.
//!
//! Each submodule exposes `pub fn rules() -> &'static [DestructiveRule]` with the
//! SAME shape as [`crate::gate::taxonomy::rules`] — no new abstraction, just more
//! per-leg rules. A pack is enabled by NAME via `config.packs`; unknown names are
//! ignored. With an empty `config.packs` (the default) [`enabled_rules`] yields
//! nothing, so the gate is byte-identical to the no-packs build.

pub mod cloud;
pub mod container;
pub mod db;

use crate::gate::taxonomy::DestructiveRule;

/// Resolve a pack NAME to its rule slice. Unknown names resolve to `None` and
/// are silently ignored by [`enabled_rules`] (forward-compatible config).
fn rules_for(name: &str) -> Option<&'static [DestructiveRule]> {
    match name {
        "cloud" => Some(cloud::rules()),
        "db" => Some(db::rules()),
        "container" => Some(container::rules()),
        _ => None,
    }
}

/// The union of rules for every enabled pack name, in `names` order.
///
/// Iterator of `&'static DestructiveRule` so the gate can chain it onto
/// [`crate::gate::taxonomy::rules`] without allocating. Empty `names` yields an
/// empty iterator (packs OFF by default → no behavior change).
//
// TODO(v0.2.x): rule-level exclude (a `pack_exclude: Vec<String>` of rule ids)
// — include-only for now to avoid over-engineering the v0.1 keystone.
pub fn enabled_rules(names: &[String]) -> impl Iterator<Item = &'static DestructiveRule> + '_ {
    names
        .iter()
        .filter_map(|name| rules_for(name))
        .flat_map(|slice| slice.iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_packs_yield_no_rules() {
        assert_eq!(enabled_rules(&[]).count(), 0);
    }

    #[test]
    fn unknown_pack_name_is_ignored() {
        let names = vec!["does-not-exist".to_string()];
        assert_eq!(enabled_rules(&names).count(), 0);
    }

    #[test]
    fn known_pack_resolves_to_its_rules() {
        let names = vec!["cloud".to_string()];
        assert_eq!(enabled_rules(&names).count(), cloud::rules().len());
    }

    #[test]
    fn multiple_packs_union_in_order() {
        let names = vec!["db".to_string(), "container".to_string()];
        let expected = db::rules().len() + container::rules().len();
        assert_eq!(enabled_rules(&names).count(), expected);
    }
}
