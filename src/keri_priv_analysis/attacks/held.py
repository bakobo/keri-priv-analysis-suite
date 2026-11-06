"""Attacks on what every verifier holds by design: the presented credential's own bytes and the
holder AID's KEL it resolves to verify the presentation (red team, 2026-10-17)."""

from __future__ import annotations

from collections import defaultdict
from math import comb

from .. import cesr
from ..model import CompartmentSet, Join, Knowledge
from .common import join_groups


def _first_acdc(raw: bytes) -> dict | None:
    for sad in cesr.messages(raw):
        if "s" in sad and "a" in sad:
            return sad
    return None


def _payload_values(acdc: dict) -> list[tuple[str, str]]:
    """Values that a fresh copy makes unique to itself: the attribute and edge sections, their
    SAIDs when compact, salts, and the credentials edges point to."""
    out = []
    for section in ("a", "e", "r"):
        value = acdc.get(section)
        if isinstance(value, str):
            out.append((section, value))
        elif isinstance(value, dict):
            out += [(f"{section}.d", value["d"])] if "d" in value else []
            out += [(f"{section}.u", value["u"])] if "u" in value else []
            for name, node in value.items():
                if isinstance(node, dict) and "n" in node:
                    out.append((f"{section}.{name}.n", node["n"]))
    return out


def payload_invariance(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Presented credentials that share a value a fresh copy would make unique: a cloned
    attribute block, a shared edge to a per-citizen credential, a reused salt."""
    groups = defaultdict(set)
    said_of = {}
    public = set(k.infrastructure)
    for p in cs.presentations():
        acdc = _first_acdc(p.raw)
        if acdc is None:
            continue
        said_of[p.handle] = acdc["d"]
        for value in _payload_values(acdc):
            if value[1] not in public:  # an edge to the agency credential everyone carries
                groups[value].add(acdc["d"])
    groups = {v: saids for v, saids in groups.items() if len(saids) > 1}
    return join_groups(groups, cs.presentations(), lambda p: said_of.get(p.handle), k.per_citizen,
                       "payload-invariance")


def holder_kel(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Holder AIDs whose KELs name the same delegator, or the same witness set: a verifier must
    resolve the holder's KEL to verify a presentation, so it holds both.

    A delegator is one citizen's, so sharing one is certain. Witness sets also collide by chance
    when each AID draws its own from a shared pool, so a witness-set join is discounted by how
    much more often AIDs share a set than random draws from the observed pool would.
    """
    delegated, witnessed = defaultdict(set), defaultdict(set)
    for compartment in cs.of_kind("verifier"):
        for name, data in compartment.streams.items():
            if not name.startswith("kel:"):
                continue
            # The holder's own inception: a delegated holder's stream opens with its delegator's
            # KEL, which the verifier resolved too.
            holder = name.removeprefix("kel:")
            inception = next((e for e in cesr.messages(data, name)
                              if e.get("i") == holder and e.get("t") in ("icp", "dip")), None)
            if inception is None:
                continue
            if inception.get("di"):
                delegated[inception["di"]].add(inception["i"])
            if inception.get("b"):
                witnessed[tuple(sorted(inception["b"]))].add(inception["i"])
    held = cs.presentations()
    joins = join_groups(delegated, held, lambda p: p.holder, k.per_citizen, "holder-kel")
    aids = sum(len(group) for group in witnessed.values())
    if aids < 2:
        return joins
    shared = sum(len(group) for group in witnessed.values() if len(group) > 1) / aids
    pool = {w for key in witnessed for w in key}
    size = max(len(key) for key in witnessed)
    chance = 1 - (1 - 1 / comb(len(pool), size)) ** (aids - 1)
    weight = max(0.0, (shared - chance) / shared) if shared else 0.0
    for j in join_groups(witnessed, held, lambda p: p.holder, k.per_citizen, "holder-kel"):
        joins.append(Join(j.a, j.b, j.confidence * weight, j.attack))
    return joins


def shared_holder(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Presentations made by one holder AID: a stack that gives a citizen one AID for every copy,
    KERIA's ordinary usage, links them all (found by the KERIA adapter, 2026-10-17)."""
    groups = defaultdict(set)
    for p in cs.presentations():
        groups[p.holder].add(p.said)
    return join_groups({h: [h] for h in groups}, cs.presentations(), lambda p: p.holder,
                       k.per_citizen, "shared-holder", size=lambda h: len(groups[h]))
