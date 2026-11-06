"""Attacks on what the protocol publishes: registries, KEL anchors, TEL timestamps and batches."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from .. import cesr
from ..model import CompartmentSet, Join, Knowledge, identifiers
from .common import join_groups, read_record, sessions


def _seconds(dt: str) -> float:
    return datetime.fromisoformat(dt).timestamp()


def _credentials_in(record, registry: str) -> int:
    """How many credentials a registry's TEL shows it holding: the distinct credentials its
    updates name, so status updates to the same credential are not counted again. A blinded
    update names none, and then every update is taken as a credential, the cautious count."""
    updates = record.updates(registry)
    named = {e["credential"] for e in updates if e["credential"]}
    if all(e["credential"] for e in updates):
        return max(1, len(named))
    return max(1, len(updates))


def shared_registry(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Two credentials in one registry. The registry's TEL says how many credentials it holds,
    which sets how sure a join is."""
    record = read_record(cs)
    groups = {regid: [regid] for regid in record.tels}
    return join_groups(groups, cs.presentations(), lambda p: p.registry, k.per_citizen,
                       "shared-registry", size=lambda g: _credentials_in(record, g))


def _runs(events: list[dict], keep) -> dict[int, tuple[int, int]]:
    """For each KEL sequence number in a run of consecutive events `keep` accepts, the run's
    number and the event's position in it."""
    out, run, position = {}, 0, 0
    for event in events:
        if keep(event):
            out[int(event["s"], 16)] = (run, position)
            position += 1
        else:
            if position:
                run += 1
            position = 0
    return out


def _block_joins(record, held, k, sealed_of, keep, block, attack) -> list[Join]:
    """Join held presentations whose sealed event sits in the same aligned block of a run."""
    runs = {issuer: _runs(events, keep) for issuer, events in record.kels.items()}
    lengths = defaultdict(int)
    for issuer, positions in runs.items():
        for run, _ in positions.values():
            lengths[(issuer, run)] += 1
    groups = defaultdict(list)
    for p in held:
        said = sealed_of(p)
        if said not in record.seals:
            continue
        issuer, sn, _ = record.seals[said]
        if sn not in runs[issuer]:
            continue
        run, position = runs[issuer][sn]
        groups[(issuer, run, position // block)].append(p.handle)
    joins = []
    for (issuer, run, _), handles in groups.items():
        conf = 1.0 if lengths[(issuer, run)] % block == 0 else 0.5
        joins += [Join("p:" + a, "p:" + b, conf, attack)
                  for i, a in enumerate(sorted(handles)) for b in sorted(handles)[i + 1:]]
    return joins


def kel_anchor_adjacency(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Issuance anchors at nearby sequence numbers (F1). A run of interaction events each sealing
    one issuance is cut into blocks of the issuance block the State's policy fixes."""
    record = read_record(cs)
    events = record.events()

    def issuance(event):
        seals = event.get("a", [])
        return (event["t"] == "ixn" and len(seals) == 1 and seals[0].get("d") in events
                and events[seals[0]["d"]]["kind"] == "update")

    def sealed_of(p):
        event = record.issuance(p)
        return event["d"] if event else None
    return _block_joins(record, cs.presentations(), k, sealed_of, issuance, k.issuance_block,
                        "kel-anchor-adjacency")


def registry_inception_adjacency(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Registry inception seals at nearby sequence numbers (F1): a pool incepted in a loop and
    handed out in order gives one citizen consecutive registries."""
    record = read_record(cs)
    events = record.events()

    def inception(event):
        # Only registries that went on to issue: an issuer's own registry incepted before the
        # pool, or a pool registry never handed out, would shift every block after it.
        seals = event.get("a", [])
        return (event["t"] == "ixn" and len(seals) == 1 and seals[0].get("d") in events
                and events[seals[0]["d"]]["kind"] == "inception"
                and bool(record.updates(events[seals[0]["d"]]["registry"])))
    return _block_joins(record, cs.presentations(), k, lambda p: p.registry, inception, k.per_citizen,
                        "registry-inception-adjacency")


def timestamp_clustering(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """TEL event `dt` values close in time (F2), blinded `bup` included: one citizen's copies are
    issued milliseconds apart, so a session stands out from its neighbours."""
    record = read_record(cs)
    times = {e["d"]: _seconds(e["dt"]) for e in record.events().values()
             if e["kind"] == "update" and e["dt"]}
    groups = sessions(times, k.per_citizen)

    def key(p):
        event = record.issuance(p)
        return event["d"] if event else None
    return join_groups(groups, cs.presentations(), key, k.per_citizen, "timestamp-clustering")


def event_count_lockstep(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Registries whose sequence numbers advance together (F6): their updates are sealed in one
    interaction event."""
    record = read_record(cs)
    events = record.events()
    groups = {}
    for issuer, kel in record.kels.items():
        for event in kel:
            regs = [events[s["d"]]["registry"] for s in event.get("a", [])
                    if s.get("d") in events and events[s["d"]]["kind"] == "update"]
            if len(regs) > 1:
                groups[(issuer, event["s"])] = regs
    return join_groups(groups, cs.presentations(), lambda p: p.registry, k.per_citizen,
                       "event-count-lockstep")


def shared_batch_root(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Two credentials under one batch commitment (F7). Generator only until a stack commits to batches."""
    record = read_record(cs)
    groups = dict(enumerate(record.batches))
    return join_groups(groups, cs.presentations(), lambda p: p.registry, k.per_citizen,
                       "shared-batch-root")


def shared_anchor(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Registries whose events, inceptions or issuances, are sealed in one interaction event: an
    issuer that anchors one citizen's copies together links them for everyone who reads its KEL."""
    record = read_record(cs)
    events = record.events()
    groups = {}
    for issuer, kel in record.kels.items():
        for event in kel:
            regs = sorted({events[s["d"]]["registry"] for s in event.get("a", [])
                           if s.get("d") in events})
            if len(regs) > 1:
                groups[(issuer, event["s"])] = regs
    return join_groups(groups, cs.presentations(), lambda p: p.registry, k.per_citizen,
                       "shared-anchor")


def batch_order(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Registries next to each other inside the Registrar's published batches: a batch that mixes
    citizens but lists heads in issuance order keeps each citizen's run of copies together."""
    record = read_record(cs)
    order = [regid for batch in record.batches for regid in batch]
    groups = {}
    for position, regid in enumerate(order):
        groups.setdefault(position // k.per_citizen, []).append(regid)
    return join_groups(groups, cs.presentations(), lambda p: p.registry, k.per_citizen, "batch-order")


def _anchoring_events(record) -> dict[str, str]:
    """For each TEL update's SAID, the SAID of the KEL event sealing it."""
    by_sn = {(issuer, int(e["s"], 16)): e["d"] for issuer, kel in record.kels.items()
             for e in kel}
    return {said: by_sn[(issuer, sn)] for said, (issuer, sn, _) in record.seals.items()
            if (issuer, sn) in by_sn}


def _anchor_time_joins(cs, k, times: dict[str, float], attack: str) -> list[Join]:
    """Join presentations whose issuance was anchored in KEL events close in time."""
    record = read_record(cs)
    anchoring = _anchoring_events(record)
    events = record.events()
    issuing = {anchoring[d] for d, e in events.items() if e["kind"] == "update" and d in anchoring}
    groups = sessions({d: t for d, t in times.items() if d in issuing}, k.per_citizen)

    def key(p):
        event = record.issuance(p)
        return anchoring.get(event["d"]) if event else None
    return join_groups(groups, cs.presentations(), key, k.per_citizen, attack)


def kel_first_seen(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """First-seen times in the issuer's KEL replay, which keripy attaches to every event from the
    replaying node's clock, untouched by any coarsening of TEL `dt` (red team, 2026-10-17)."""
    times = {}
    for compartment in cs.of_kind("public"):
        for name, data in compartment.streams.items():
            if name.startswith("kel:"):
                times |= cesr.first_seen(data, name)
    return _anchor_time_joins(cs, k, times, "kel-first-seen")


def witness_arrival(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """When the State's witnesses received each issuer event, from their access logs: arrival is
    wall-clock time, which no TEL `dt` granularity reaches (red team, 2026-10-17)."""
    times = {}
    for compartment in cs.of_kind("access-log"):
        if compartment.instance != "witness":
            continue
        for line in compartment.logs:
            for said in identifiers(line.text):
                times[said] = min(times.get(said, line.time), line.time)
    return _anchor_time_joins(cs, k, times, "witness-arrival")
