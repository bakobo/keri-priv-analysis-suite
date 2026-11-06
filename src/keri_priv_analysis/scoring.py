"""Score one party's joins against ground truth (docs/test-plan.md, 'Metrics'; this.i 08cl03nc)."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from math import comb

from .model import CompartmentSet, GroundTruth, Join, Observation, identifiers
from .population import Population

CERTAIN = 1.0


@dataclass(frozen=True)
class PartyTerms:
    """What the scorer needs to know about a party beyond what it holds."""

    kind: str
    terms: frozenset[str]  # compartments whose holder accepted terms forbidding correlation
    context_bits: float  # bits the party's own presentation context gives it, per citizen


@dataclass
class PartyScore:
    threshold_bits: float
    joins: int
    direct_correct: int
    certain_share: float | None
    precision: float | None
    recall: float | None
    bits: list[float]
    reidentified: int
    sensitive_exposed: dict[str, int]
    identity_exposed: int
    bound_joins: int
    breach_bits: list[float]
    breach_reidentified: int
    increment: list[float]
    completeness: dict[str, dict[int, float]] = field(default_factory=dict)
    flagged: dict[str, bool] = field(default_factory=dict)

    def to_json(self) -> dict:
        out = dict(vars(self))
        out["completeness"] = {d: {str(c): v for c, v in per.items()}
                               for d, per in self.completeness.items()}
        return out


class _Clusters:
    """Union-find over nodes, remembering whether every join inside a cluster was certain."""

    def __init__(self, nodes):
        self.parent = {n: n for n in nodes}
        self.uncertain = set()

    def find(self, n):
        self.parent.setdefault(n, n)
        while self.parent[n] != n:
            self.parent[n] = self.parent[self.parent[n]]
            n = self.parent[n]
        return n

    def union(self, a, b, certain):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb
            if ra in self.uncertain:
                self.uncertain.add(rb)
        if not certain:
            self.uncertain.add(rb)

    def groups(self):
        out = defaultdict(list)
        for n in list(self.parent):
            out[self.find(n)].append(n)
        return out


def _bits_and_exposure(clusters, truth, population, held, observed, citizens):
    """Per-citizen bits, re-identification and sensitive exposure, from one clustering."""
    bits = [0.0] * citizens
    reid_attrs: dict[int, dict[str, str]] = {}
    identity_exposed = set()
    for members in clusters.groups().values():
        own = defaultdict(dict)
        identified, artifacts = set(), set()
        for node in members:
            citizen = truth.citizen_of(node)
            if citizen is None:
                continue
            if node.startswith("id:"):
                identified.add(citizen)
            elif node.startswith("x:"):
                artifacts.add(citizen)
            else:
                row = population.row(truth.citizen_rows[citizen])
                own[citizen].update(held[node])
                own[citizen].update((a, v) for a, v in observed.get(node, ()) if row[a] == v)
        identity_exposed |= identified & (artifacts | own.keys())
        for citizen, attrs in own.items():
            value = population.max_bits if citizen in identified else population.bits(attrs)
            bits[citizen] = max(bits[citizen], value)
            if value >= population.max_bits - 1e-9:
                reid_attrs.setdefault(citizen, {}).update(attrs)
    sensitive = Counter(a for attrs in reid_attrs.values() for a in attrs
                        if a in population.sensitive)
    return bits, len(reid_attrs), dict(sensitive), len(identity_exposed)


def _sources(held: CompartmentSet, presented: dict[str, str]) -> dict[str, set[str]]:
    """Which compartments each node's evidence comes from: a presentation's verifier, and every
    compartment whose records or log lines carry an identifier or an identity record."""
    where = defaultdict(set)
    for node, name in presented.items():
        where[node].add(name)
    for compartment in held.present():
        texts = [line.text for line in compartment.logs]
        for rows in compartment.records.values():
            for row in rows:
                texts.append(" ".join(row.values()))
                if "record" in row:
                    where["id:" + row["record"]].add(compartment.name)
        for text in texts:
            for identifier in identifiers(text):
                where["x:" + identifier].add(compartment.name)
    return where


def score(party: PartyTerms, held: CompartmentSet, joins: list[Join],
          observations: list[Observation], truth: GroundTruth, population: Population,
          cut: float, mandatory: dict[str, bool]) -> PartyScore:
    citizens = len(truth.citizen_rows)
    source = {}
    disclosed = {}
    for compartment in held.present():
        for p in compartment.presentations:
            source["p:" + p.handle] = compartment.name
            disclosed["p:" + p.handle] = p.disclosed
    observed = defaultdict(list)
    for o in observations:
        observed[o.node].append((o.attribute, o.value))

    used = [j for j in joins if j.confidence >= cut]
    bindable = party.kind != "government" and bool(party.terms)
    where = _sources(held, source) if bindable else {}

    def under_terms(node):
        found = where.get(node)
        return bool(found) and found <= party.terms

    is_bound = [bindable and (under_terms(j.a) or under_terms(j.b)) for j in used]
    bound = [j for j, b in zip(used, is_bound, strict=True) if b]
    free = [j for j, b in zip(used, is_bound, strict=True) if not b]

    def clustering(js):
        c = _Clusters(disclosed)
        for j in js:
            c.union(j.a, j.b, j.confidence >= CERTAIN)
        return c

    harm, breach = clustering(free), clustering(used)
    bits, reid, sensitive, identity_exposed = _bits_and_exposure(
        harm, truth, population, disclosed, observed, citizens)
    breach_bits, breach_reid, _, _ = _bits_and_exposure(
        breach, truth, population, disclosed, observed, citizens)

    # Precision and recall over pairs of held presentations that share a cluster.
    in_cluster = right = 0
    for members in harm.groups().values():
        held_here = [truth.citizen_of(n) for n in members if n in disclosed]
        in_cluster += comb(len(held_here), 2)
        right += sum(comb(k, 2) for k in Counter(held_here).values())
    per_citizen = Counter(truth.citizen_of(n) for n in disclosed)
    possible = sum(comb(k, 2) for k in per_citizen.values())

    # Completeness: per domain, the share of each citizen's events that one cluster holds.
    events = defaultdict(lambda: defaultdict(set))
    for handle, citizen in truth.presentations.items():
        events[truth.domains[handle]][citizen].add("p:" + handle)
    completeness, flagged = {}, {}
    groups = harm.groups()
    for domain, per in events.items():
        completeness[domain] = {}
        for citizen, nodes in per.items():
            best, certain = 0.0, False
            for root, members in groups.items():
                share = len(nodes & set(members)) / len(nodes)
                if share > best:
                    best, certain = share, root not in harm.uncertain
            completeness[domain][citizen] = best
            if best == 1.0 and certain and len(nodes) >= 2:
                flagged[domain] = mandatory[domain]

    return PartyScore(
        threshold_bits=population.max_bits,
        joins=len(used),
        direct_correct=sum(1 for j in used if truth.citizen_of(j.a) is not None
                           and truth.citizen_of(j.a) == truth.citizen_of(j.b)),
        certain_share=(sum(1 for j in used if j.confidence >= CERTAIN) / len(used)
                       if used else None),
        precision=right / in_cluster if in_cluster else None,
        recall=right / possible if possible else None,
        bits=bits,
        reidentified=reid,
        sensitive_exposed=sensitive,
        identity_exposed=identity_exposed,
        bound_joins=len(bound),
        breach_bits=breach_bits,
        breach_reidentified=breach_reid,
        increment=[max(0.0, b - party.context_bits) for b in bits],
        completeness=completeness,
        flagged=flagged,
    )
