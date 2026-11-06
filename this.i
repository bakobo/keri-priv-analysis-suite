# keri-priv-analysis-suite — Intent Tree (this.i)
#
# Source of truth for this repo's intentions and the decisions that follow from them. Each
# consequential decision is recorded here, in its own commit, before the code that implements it.
# Ids are minted by `i id` and never typed.
#
# Origin: a design review held 2026-10-14 to 2026-10-16 for a state digital-identity deployment.
# Its record cites private correspondence and is not part of this repository.

Measure what a KERI/ACDC deployment lets each adversary join about a citizen, on any implementation = goal:
  nid: 34te7g4t
  why: >-
    A deployment that issues bulk ACDC copies to citizens relies on mitigations (one registry per credential, a fresh holder AID per copy, unique nonces) to keep two verifiers who compare notes from linking a citizen's presentations, and needs to show those mitigations work against registry, timestamp, batch, AID and network-observation correlation. Nobody had attacked them, and reading a custodial issuer's source during the design review predicted at least two leaks (KEL adjacency of a citizen's copies, microsecond `dt` on every blinded TEL event) that link a citizen's bulk copies. Chose a stack-agnostic suite in its own repo, beside keri-conformance-suite, over attack tests inside the issuer, because the same instrument must rerun against KERIA or any other stack, and a privacy verdict produced by the vendor's own tests is weak evidence. Tradeoff: an adapter layer that in-repo tests would not need.
