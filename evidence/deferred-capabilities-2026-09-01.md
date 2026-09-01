# Deferred Capabilities — apohara-agentguard (2026-09-01)

**Status:** All deferred — require explicit maintainer approval before implementation
**Source:** OpenSpec `release-governance-evidence/specs/deferred-capabilities/spec.md`

---

## 1. ADR: Persistent Budgets

**Capability:** Persist token/invocation budgets across hook invocations (currently reset per-process)

**Threat model:** XDG state corruption, locking contention, crash recovery, disk limits, multi-process races, benchmark <5µs requirement

**Current state:** Budgets reset per hook event (fresh process). Documented as intentional design choice.

**Decision required:** Maintainer approval (`Approved-by`) before:
- Persisting budget state to disk
- Adding file locking dependencies
- Changing default build behavior

**Gate:** ❌ NOT APPROVED — no `Approvedby` label

---

## 2. ADR: Ed25519 Signing

**Capability:** Ed25519 per-decision signing with hash chain (SHA-256), trust anchor, key custody, rotation, offline verification

**Current state:** Audit trail uses hash chain but no cryptographic signing. Fase 3 of original roadmap.

**Decision required:** Maintainer approval before:
- Adding signing dependencies (ring/ed25519-dalek)
- Defining trust anchor format
- Implementing key rotation
- Changing audit trail format

**Gate:** ❌ NOT APPROVED — awaiting compliance demand + maintainer decision

---

## 3. Revalidation: eBPF NO-GO

**Capability:** eBPF/BPF-LSM enforcement for kernel-level sandboxing

**Current state:** Purity guard actively rejects eBPF dependencies (`aya`, `libbpf`) in default build. Negative self-test confirms this.

**Five conditions for GO (all must be met):**
1. Self-hosted runner with kernel 5.8+ available
2. Landlock enforcement proven in CI (PROFILE_OK ×5)
3. Purity guard exception explicitly approved
4. Performance budget defined (<5µs overhead)
5. Maintainer `Approved-by` on spike PR

**Current assessment:** ❌ NO-GO — conditions 1, 3, 4, 5 not met. Landlock (condition 2) is progressing.

**Gate:** ❌ NOT APPROVED — purity guard continues to reject eBPF dependencies

---

## 4. Revalidation: Semantic Tier (Sidecar Advisory)

**Capability:** MiniBERT sidecar for semantic risk classification (advisory-only, never Deny)

**Current state:** Advisory-only as designed. Can escalate Allow→Ask but never auto-Allow or Deny.

**Conditions for expansion:**
1. External demand demonstrated
2. Signed model artifact
3. p95 latency budget defined
4. Never changes default build
5. Never emits Deny

**Current assessment:** ⏸️ DEFERRED — no external demand, no signed model. Existing advisory-only behavior is correct.

**Gate:** ❌ NOT APPROVED — no external demand

---

## 5. Summary

| Capability | Status | Blocking Factor |
|------------|--------|-----------------|
| Persistent budgets | ❌ Deferred | No maintainer approval, threat model incomplete |
| Ed25519 signing | ❌ Deferred | No compliance demand, no maintainer approval |
| eBPF enforcement | ❌ NO-GO | 4/5 conditions unmet, purity guard active |
| Semantic tier expansion | ⏸️ Deferred | No external demand, no signed model |

**All four capabilities remain deferred by design.** Implementation requires explicit maintainer approval with `Approved-by` label on a dedicated PR. Research, benchmarking, and threat modeling are permitted without approval.
