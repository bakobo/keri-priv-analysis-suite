"""What several attacks share: reading the public record, grouping, and emitting joins."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from functools import cached_property, lru_cache
from itertools import combinations
from math import isnan

from .. import cesr, errors
from ..model import CompartmentSet, Join, Presentation


@dataclass
class Record:
    """The public record, read once: every registry's TEL events, of either generation, and where
    each event is sealed in its issuer's KEL.

    Each TEL event is kept as cesr.tel_event gives it, plus its SAID `d` and its `dt`.
    """

    tels: dict[str, list[dict]]  # registry -> its events, in stream order, inception first
    seals: dict[str, tuple[str, int, int]]  # event SAID -> (issuer, KEL sn, seal position)
    kels: dict[str, list[dict]]  # issuer -> events
    batches: list[list[str]]  # registry ids per published batch

    @cached_property
    def _events(self) -> dict[str, dict]:
        return {e["d"]: e for events in self.tels.values() for e in events}

    @cached_property
    def _updates(self) -> dict[str, list[dict]]:
        return {r: [e for e in events if e["kind"] == "update"] for r, events in self.tels.items()}

    def events(self) -> dict[str, dict]:
        return self._events

    def updates(self, registry: str) -> list[dict]:
        return self._updates.get(registry, [])

    def issuance(self, p: Presentation) -> dict | None:
        """The TEL event that issued a presented credential.

        A public `upd` or a v1 `iss` names the credential; a blinded `bup` does not, and then the
        registry's first update is taken, which is right for a registry per credential.
        """
        updates = self.updates(p.registry)
        for event in updates:
            if event["credential"] == p.said:
                return event
        return updates[0] if updates else None


def read_record(cs: CompartmentSet) -> Record:
    """The public record the party holds, parsed once however many attacks and parties read it."""
    streams = tuple(item for c in cs.of_kind("public") for item in sorted(c.streams.items()))
    return _parsed(streams)


@lru_cache(maxsize=8)
def _parsed(streams: tuple[tuple[str, bytes], ...]) -> Record:
    tels, kels, seals, batches = defaultdict(list), {}, {}, []
    for name, data in streams:
        if name.startswith("kel:"):
            kels[name.removeprefix("kel:")] = cesr.messages(data, name)
        elif name.startswith("tel:"):
            for event in cesr.messages(data, name):
                e = cesr.tel_event(event)
                tels[e["registry"]].append({**e, "d": event["d"], "dt": event.get("dt")})
        elif name.startswith("batch:"):
            batches.append(_batch(name, data))
    for issuer, events in kels.items():
        for said, (sn, position) in cesr.seals(events).items():
            seals[said] = (issuer, sn, position)
    return Record(tels=dict(tels), seals=seals, kels=kels, batches=batches)


def _batch(name: str, data: bytes) -> list[str]:
    try:
        doc = json.loads(data)
    except ValueError:
        doc = None
    registries = doc.get("registries") if isinstance(doc, dict) else None
    if not (isinstance(registries, list) and all(isinstance(r, str) for r in registries)):
        raise errors.STREAM_SHAPE(name=name, reason='a batch is a JSON object whose "registries" '
                                  "is a list of registry ids")
    return registries


def confidence(group: int, copies: int) -> float:
    """How sure a join inside a group is, when each citizen contributes `copies` members.

    A group no bigger than one citizen's copies is taken as one citizen's: certain. A bigger group
    holds group/copies citizens, and two of its members share a citizen with probability about
    (copies - 1) / (group - 1). Overlapping sessions can make a small group span citizens, so
    "certain" is the attack's claim and the scorer's precision is the check on it (~4cul).
    """
    if group <= copies:
        return 1.0
    return (copies - 1) / (group - 1)


def clique(handles, conf: float, attack: str) -> list[Join]:
    return [Join("p:" + a, "p:" + b, conf, attack) for a, b in combinations(sorted(set(handles)), 2)]


def join_groups(groups: dict, held: list[Presentation], key, copies: int, attack: str,
                size=None) -> list[Join]:
    """Join held presentations whose `key` falls in the same group.

    `groups` maps a group to the keys in it, and a key may sit in several groups. `size` gives a
    group's size for its confidence, by default the number of distinct keys in it, since the
    attacker sees the whole group whether or not it holds a presentation for each member.
    """
    member = defaultdict(list)
    for group, keys in groups.items():
        for k in set(keys):
            member[k].append(group)
    by_group = defaultdict(list)
    for p in held:
        for group in member.get(key(p), ()):
            by_group[group].append(p.handle)
    joins = []
    for group, handles in by_group.items():
        n = size(group) if size else len(set(groups[group]))
        joins += clique(handles, confidence(n, copies), attack)
    return joins


def sessions(times: dict[str, float], per_citizen: int) -> dict[int, list[str]]:
    """Split keys, ordered by time, into as many runs as there are sessions of `per_citizen`
    events, cutting at the widest gaps.

    No gap threshold is assumed: a stack whose issuances sit milliseconds apart and one whose
    witness receipts space them seconds apart split the same way, as long as sessions are further
    apart than the events inside them. Where they are not, the runs are arbitrary, which scores
    at chance. NaN times are left out.
    """
    ordered = sorted(((t, key) for key, t in times.items() if not isnan(t)),
                     key=lambda x: (x[0], x[1]))
    count = max(1, round(len(ordered) / max(1, per_citizen)))
    gaps = sorted(range(1, len(ordered)), key=lambda i: (-(ordered[i][0] - ordered[i - 1][0]), i))
    cuts = set(gaps[:count - 1])
    out, n = defaultdict(list), 0
    for i, (_, key) in enumerate(ordered):
        if i in cuts:
            n += 1
        out[n].append(key)
    return out
