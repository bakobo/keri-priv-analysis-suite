"""Attacks on what infrastructure logs: holder-AID services, registry reads, hosted agents, and a
verifier's own probing (this.i 5y304fhq)."""

from __future__ import annotations

from collections import defaultdict

from ..model import CompartmentSet, Join, Knowledge, identifiers
from .common import join_groups, sessions

# A line of a verifier's own probe log: when it first saw a registry on the Registrar's feed.
PROBE = "first-seen "


def _by_source(cs, roles, k, wanted) -> dict[str, set[str]]:
    """Identifiers each source address touched, in the named access logs, leaving out the
    addresses everyone knows: verifiers' and the State's own services'."""
    known = set(k.verifier_addresses) | set(k.service_addresses)
    groups = defaultdict(set)
    for compartment in cs.of_kind("access-log"):
        if compartment.instance not in roles:
            continue
        for line in compartment.logs:
            if line.source in known:
                continue
            groups[line.source] |= {i for i in identifiers(line.text) if wanted(i)}
    return groups


def holder_infrastructure(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Holder AIDs registered with the same mailbox and witness from one address (F5)."""
    held = cs.presentations()
    holders = {p.holder for p in held}
    groups = _by_source(cs, ("mailbox", "holder-witness"), k, lambda i: True)
    groups = {a: ids for a, ids in groups.items() if ids & holders}
    return join_groups(groups, held, lambda p: p.holder, k.per_citizen, "holder-infrastructure")


def registry_reads(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Registries read from one address, in the Observer's and Registrar's logs (F4). Verifiers'
    and the State's own addresses are known and left out, so what groups is a holder's wallet
    checking the status of its own copies from its own address."""
    held = cs.presentations()
    groups = _by_source(cs, ("observer", "registrar"), k, lambda i: True)
    return join_groups(groups, held, lambda p: p.registry, k.per_citizen, "registry-reads")


def hosted_agent(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Holder AIDs one hosted agent serves (F-CVNP), from the hosting service's own log. A line
    names its agent by any identifier on it that is not a presented holder AID, or else by its
    text with the identifiers taken out, so any log format reads."""
    held = cs.presentations()
    holders = {p.holder for p in held}
    public = set(k.infrastructure)
    groups = defaultdict(set)
    for compartment in cs.of_kind("access-log"):
        if compartment.instance != "hosted-agent":
            continue
        for line in compartment.logs:
            ids = [i for i in identifiers(line.text) if i not in public]
            served = {i for i in ids if i in holders}
            agents = [i for i in ids if i not in holders] or [
                " ".join(t for t in line.text.split() if t not in ids)]
            for agent in agents:
                groups[agent] |= served
    return join_groups(groups, held, lambda p: p.holder, k.per_citizen, "hosted-agent")


def agent_end_role(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Holder AIDs whose end-role records name the same agent: a verifier resolving a holder AID
    stores the reply that names the agent serving it, and one agent serves a citizen's every AID
    (found by the KERIA adapter, 2026-10-17). An agent the State runs for many citizens is
    infrastructure, and sharing it says nothing about who a holder is."""
    public = set(k.infrastructure)
    groups = defaultdict(set)
    for compartment in cs.of_kind("verifier"):
        for rows in compartment.records.values():
            for row in rows:
                if (row.get("role") in ("agent", "mailbox") and row.get("aid")
                        and row.get("eid") and row["eid"] not in public):
                    groups[row["eid"]].add(row["aid"])
    return join_groups(groups, cs.presentations(), lambda p: p.holder, k.per_citizen,
                       "agent-end-role")


def verifier_probing(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """When a verifier first saw each registry, from polling the Registrar's feed itself (Q4):
    registries published together were issued together."""
    first = {}
    for compartment in cs.of_kind("verifier"):
        for line in compartment.logs:
            if not line.text.startswith(PROBE):
                continue  # the verifier's ordinary log is not a probe log
            for regid in identifiers(line.text):
                first[regid] = min(first.get(regid, line.time), line.time)
    groups = sessions(first, k.per_citizen)
    return join_groups(groups, cs.presentations(), lambda p: p.registry, k.per_citizen,
                       "verifier-probing")
