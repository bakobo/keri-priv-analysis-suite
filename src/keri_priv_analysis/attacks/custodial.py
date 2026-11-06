"""Attacks on what the State's own stores and logs hold (F3, this.i 4ww9snv2)."""

from __future__ import annotations

import re
from collections import defaultdict
from itertools import pairwise

from ..model import CompartmentSet, Join, Knowledge, identifiers
from .common import clique


def _identity_records(cs: CompartmentSet) -> dict[str, list[str]]:
    """Management key -> every identity record that names it, from every compartment that
    retains one. None replaces another: an attacker holding both rows can follow either, and a
    later unrelated row must not hide a valid join from scoring."""
    out = defaultdict(dict)  # an ordered set per key: one record seen twice is one record
    for compartment in cs.present():
        for rows in compartment.records.values():
            for row in rows:
                if "management" in row and "record" in row:
                    out[row["management"]][row["record"]] = None
    return {key: list(records) for key, records in out.items()}


def custodial_join(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """The stored map from a credential's identifiers to the citizen's management AID, and from
    that to a legal identity, read directly."""
    key_of = {}
    for compartment in cs.of_kind("issuing-home") + cs.of_kind("revocation-authority"):
        for rows in compartment.records.values():
            for row in rows:
                if "management" not in row:
                    continue
                for field in ("said", "registry", "holder"):
                    if field in row:
                        key_of[row[field]] = row["management"]
    identity = _identity_records(cs)
    name = "custodial-join"
    by_key = defaultdict(list)
    joins = []
    for p in cs.presentations():
        key = key_of.get(p.said) or key_of.get(p.registry) or key_of.get(p.holder)
        if key is None:
            continue
        by_key[key].append(p.handle)
        joins += [Join("p:" + p.handle, "id:" + record, 1.0, name)
                  for record in identity.get(key, ())]
    for handles in by_key.values():
        joins += clique(handles, 1.0, name)
    for identifier, key in key_of.items():
        joins += [Join("x:" + identifier, "id:" + record, 1.0, name)
                  for record in identity.get(key, ())]
    return joins


# A correlation token: a request, trace, session, job or case id written as key=value or key:value.
CORRELATION = re.compile(
    r"(?<![A-Za-z0-9_])(trace|request|req|span|session|correlation|job|case)(?:[-_]?id)?"
    r"\s*[=:]\s*([A-Za-z0-9_-]{6,})", re.IGNORECASE)


def log_scan(cs: CompartmentSet, k: Knowledge) -> list[Join]:
    """Join material copied into any log: identifiers that share a line are joined, and so are
    identifiers on different lines of one compartment that share a request, trace, session, job
    or case id. The presentations and identity records that carry them join too."""
    name = "log-scan"
    joins, seen = [], set()
    # The State's own witnesses, schemas and parties appear beside every citizen's identifiers
    # and link none of them.
    public = set(k.infrastructure)
    for compartment in cs.present():
        traced = defaultdict(list)
        for line in compartment.logs:
            ids = [i for i in dict.fromkeys(identifiers(line.text)) if i not in public]
            for key, value in CORRELATION.findall(line.text):
                traced[(key.lower(), value)] += ids
            if len(ids) < 2:
                continue
            seen |= set(ids)
            joins += [Join("x:" + a, "x:" + b, 1.0, name) for a, b in pairwise(ids)]
        for ids in traced.values():
            ids = list(dict.fromkeys(ids))
            if len(ids) > 1:
                seen |= set(ids)
                joins += [Join("x:" + a, "x:" + b, 1.0, name) for a, b in pairwise(ids)]
    for p in cs.presentations():
        for identifier in (p.said, p.registry, p.holder):
            if identifier in seen:
                joins.append(Join("p:" + p.handle, "x:" + identifier, 1.0, name))
                break
    for key, records in _identity_records(cs).items():
        if key in seen:
            joins += [Join("id:" + record, "x:" + key, 1.0, name) for record in records]
    return joins
