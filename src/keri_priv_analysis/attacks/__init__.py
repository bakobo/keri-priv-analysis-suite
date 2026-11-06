"""The attack catalogue (docs/test-plan.md, 'The attack catalogue').

Each attack reads compartment contents only and returns joins, or, for the issuer-AID bucket,
observations. Each declares the compartments it needs, the recall it promises on its positive
control, and the generator settings of both controls (this.i 97nt9ugu).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..model import CompartmentSet, Join, Knowledge
from . import bucket, custodial, held, material, network, protocol

ANY_LOG = ("public", "verifier", "issuing-home", "orchestrator", "operation-log",
           "revocation-authority", "identity-proofing", "access-log")


@dataclass(frozen=True)
class Attack:
    name: str
    vectors: tuple[str, ...]  # the five correlation vectors it answers
    origin: tuple[str, ...]  # the catalogue's Origin column
    needs: tuple[tuple[str, ...], ...]  # each requirement: any one of these kinds or names
    kind: str  # "pairwise", "identity" or "bits"
    recall: float  # promised on the positive control
    positive: dict  # generator settings of the positive control
    negative: dict
    run: Callable[[CompartmentSet, Knowledge], list]
    # What the compartments must hold for silence to mean anything, beyond being present: a
    # compartment without the attack's material is reported as not measured, never as clean.
    material: Callable[[CompartmentSet], str | None] = material.anything

    def missing(self, cs: CompartmentSet) -> list[str]:
        """The requirements this party's compartments do not meet, in words; empty if it applies."""
        present = {c.name for c in cs.present()} | {c.kind for c in cs.present()}
        out = [" or ".join(alternatives) for alternatives in self.needs
               if not present & set(alternatives)]
        if not out and (lacking := self.material(cs)):
            out.append(lacking)
        return out


def dedupe(joins: list[Join]) -> list[Join]:
    """One join per pair of nodes, at the highest confidence any group gave it."""
    best = {}
    for j in joins:
        key = tuple(sorted((j.a, j.b)))
        if key not in best or j.confidence > best[key].confidence:
            best[key] = j
    return list(best.values())


_PUBLIC = ("public",)
_HELD = ("verifier",)

CATALOGUE = (
    Attack("shared-registry", ("registry",), ("the five vectors",), (_PUBLIC, _HELD), "pairwise", 1.0,
           {"registry_scope": "citizen"}, {"registry_scope": "issuer"},
           protocol.shared_registry),
    Attack("kel-anchor-adjacency", ("batch", "AID"), ("F1",), (_PUBLIC, _HELD), "pairwise", 1.0,
           {}, {"issuance_order": "mixed"}, protocol.kel_anchor_adjacency),
    Attack("registry-inception-adjacency", ("registry",), ("F1",), (_PUBLIC, _HELD), "pairwise",
           1.0, {}, {"registry_allocation": "random"}, protocol.registry_inception_adjacency),
    # Its positive control shuffles anchors and allocates registries at random, so only the TEL
    # stamps leak: an attack that secretly read KEL order would fail it.
    Attack("timestamp-clustering", ("timestamp",), ("F2", "public upd timing"),
           (_PUBLIC, _HELD), "pairwise", 1.0,
           {"anchor_order": "shuffled", "registry_allocation": "random"},
           {"issuance_order": "mixed", "dt_granularity": 86400.0},
           protocol.timestamp_clustering),
    Attack("event-count-lockstep", ("registry",), ("F6",), (_PUBLIC, _HELD), "pairwise", 1.0,
           {"status_updates": "lockstep"}, {"status_updates": "independent"},
           protocol.event_count_lockstep),
    Attack("shared-batch-root", ("batch",), ("F7",), (_PUBLIC, _HELD), "pairwise", 1.0,
           {"batch_size": 4, "batch_mix": "citizen"}, {"batch_size": 8, "batch_mix": "mixed"},
           protocol.shared_batch_root, material.batches),
    Attack("issuer-aid-bucket", ("AID",), ("F8", "F-J180"), (_HELD,), "bits", 0.0,
           {"home_assignment": "county"}, {}, bucket.issuer_bucket),
    Attack("holder-infrastructure", ("AID", "network"), ("F5",),
           (("access-log:mailbox", "access-log:holder-witness"), _HELD), "pairwise", 1.0,
           {}, {"holder_network": "mixed"}, network.holder_infrastructure),
    Attack("registry-reads", ("network",), ("F4",),
           (("access-log:observer", "access-log:registrar"), _HELD), "pairwise", 1.0,
           {"holder_status_reads": True},
           {"holder_status_reads": True, "holder_network": "mixed"}, network.registry_reads),
    Attack("hosted-agent", ("network",), ("F-CVNP",), (("access-log:hosted-agent",), _HELD),
           "pairwise", 1.0, {"hosted_agents": "per-citizen"}, {"hosted_agents": "shared"},
           network.hosted_agent, material.logs("access-log:hosted-agent")),
    Attack("verifier-probing", ("network",), ("the design review",), (_HELD,), "pairwise", 1.0,
           {"verifier_probing": True},
           {"verifier_probing": True, "publication_window": 86400.0, "issuance_order": "mixed"},
           network.verifier_probing, material.verifier_logs),
    Attack("custodial-join", ("registry", "timestamp", "batch", "AID", "network"), ("F3",),
           (("issuing-home", "revocation-authority"),), "identity", 1.0,
           {}, {"identity_oracle": True}, custodial.custodial_join),
    Attack("log-scan", ("registry", "timestamp", "batch", "AID", "network"),
           ("this.i 4ww9snv2",), (ANY_LOG,), "pairwise", 1.0,
           {"log_join_material": True}, {}, custodial.log_scan),
    # Added after the red team of 2026-10-17 by models from other labs.
    Attack("holder-kel", ("AID",), ("red team 2026-10-17",), (_HELD,), "pairwise", 1.0,
           {"holder_aids": "delegated"},
           {"holder_aids": "transferable", "holder_witnesses": "pool"},
           held.holder_kel, material.holder_kels),
    Attack("payload-invariance", ("AID", "registry"), ("red team 2026-10-17",), (_HELD,),
           "pairwise", 1.0, {"copy_template": "cloned-attributes"}, {},
           held.payload_invariance),
    # Added after the KERIA adapter's first run, 2026-10-17.
    Attack("shared-holder", ("AID",), ("KERIA adapter 2026-10-17",), (_HELD,), "pairwise", 1.0,
           {"holder_aids": "shared"}, {}, held.shared_holder),
    Attack("agent-end-role", ("AID", "network"), ("KERIA adapter 2026-10-17",), (_HELD,),
           "pairwise", 1.0, {"hosted_agents": "per-citizen"}, {"hosted_agents": "shared"},
           network.agent_end_role, material.end_roles),
    Attack("shared-anchor", ("batch", "registry"), ("red team 2026-10-17",), (_PUBLIC, _HELD),
           "pairwise", 1.0, {"anchor_order": "per-citizen"}, {"anchor_order": "batched"},
           protocol.shared_anchor),
    Attack("batch-order", ("batch",), ("red team 2026-10-17",), (_PUBLIC, _HELD), "pairwise",
           1.0, {"batch_size": 8, "batch_mix": "ordered"}, {"batch_size": 8, "batch_mix": "mixed"},
           protocol.batch_order, material.batches),
    Attack("kel-first-seen", ("timestamp",), ("red team 2026-10-17",), (_PUBLIC, _HELD),
           "pairwise", 1.0, {"dt_granularity": 86400.0}, {"first_seen": "constant"},
           protocol.kel_first_seen),
    Attack("witness-arrival", ("timestamp", "network"), ("red team 2026-10-17",),
           (("access-log:witness",), _PUBLIC, _HELD), "pairwise", 1.0,
           {"dt_granularity": 86400.0, "first_seen": "constant"}, {"issuance_order": "mixed"},
           protocol.witness_arrival, material.logs("access-log:witness")),
)

ATTACKS = {a.name: a for a in CATALOGUE}
