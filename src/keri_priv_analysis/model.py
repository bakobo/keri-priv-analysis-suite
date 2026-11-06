"""The compartment interface (this.i 9wxr29dq).

An adapter returns a CompartmentSet, which attacks read, and a GroundTruth, which only the scorer
and the adapter contract suite read. The two never travel together.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from math import isfinite

from . import errors

# Kinds that name one body of data, and kinds that have one instance per party or operator.
SINGLE_KINDS = ("public", "orchestrator", "operation-log", "revocation-authority",
                "identity-proofing")
INSTANCE_KINDS = ("verifier", "issuing-home", "access-log")
KINDS = SINGLE_KINDS + INSTANCE_KINDS
STATUSES = ("present", "absent", "not-measured")
IDENTIFIER = re.compile(r"(?<![A-Za-z0-9_-])[A-Z][A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")


def identifiers(text: str) -> list[str]:
    """Every token in the text shaped like a 44-character qb64 identifier."""
    return IDENTIFIER.findall(text)


def parse_compartment_name(name: str) -> tuple[str, str | None]:
    """Split a compartment name into its kind and instance, refusing any name the suite lacks."""
    kind, sep, instance = name.partition(":")
    if (kind in SINGLE_KINDS and not sep) or (kind in INSTANCE_KINDS and instance):
        return kind, instance or None
    raise errors.COMPARTMENT_NAME(name=name, kinds=", ".join(KINDS))


@dataclass(frozen=True)
class LogLine:
    """One line of a log: when, from which address, and the raw text."""

    time: float
    source: str
    text: str


@dataclass(frozen=True)
class Presentation:
    """One disclosure by one citizen to one verifier, as the verifier stored it.

    ``handle`` is opaque: an adapter mints it at random, so it says nothing about the citizen.
    """

    handle: str
    verifier: str
    time: float
    domain: str
    disclosed: dict[str, str]
    said: str
    registry: str
    issuer: str
    holder: str
    raw: bytes


@dataclass
class Compartment:
    """A body of stored data behind one access boundary (this.i 9hztf0uy)."""

    name: str
    status: str
    streams: dict[str, bytes] = field(default_factory=dict)
    records: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    logs: list[LogLine] = field(default_factory=list)
    presentations: list[Presentation] = field(default_factory=list)
    note: str = ""

    def __post_init__(self):
        self.kind, self.instance = parse_compartment_name(self.name)
        if self.status not in STATUSES:
            raise errors.COMPARTMENT_STATUS(name=self.name, status=self.status)
        if self.status != "present" and (self.streams or self.records or self.logs
                                         or self.presentations):
            raise errors.COMPARTMENT_CONTENTS(name=self.name, status=self.status)
        for what, items in (("log line", self.logs), ("presentation", self.presentations)):
            for item in items:
                number = isinstance(item.time, (int, float)) and not isinstance(item.time, bool)
                if not number or not isfinite(item.time):
                    raise errors.TIME_VALUE(name=self.name, what=what, time=item.time)


class CompartmentSet:
    """The compartments a party holds, in a stable order. It never holds ground truth."""

    def __init__(self, compartments):
        self._by_name: dict[str, Compartment] = {}
        for compartment in compartments:
            if compartment.name in self._by_name:
                raise errors.COMPARTMENT_DUPLICATE(name=compartment.name)
            self._by_name[compartment.name] = compartment

    def __getitem__(self, name: str) -> Compartment:
        return self._by_name[name]

    def __contains__(self, name: str) -> bool:
        return name in self._by_name

    def __iter__(self):
        return iter(self._by_name.values())

    def __eq__(self, other):
        return isinstance(other, CompartmentSet) and self._by_name == other._by_name

    def names(self) -> list[str]:
        return list(self._by_name)

    def present(self) -> list[Compartment]:
        return [c for c in self if c.status == "present"]

    def of_kind(self, kind: str) -> list[Compartment]:
        return [c for c in self.present() if c.kind == kind]

    def presentations(self) -> list[Presentation]:
        return [p for c in self.present() for p in c.presentations]

    def subset(self, names) -> CompartmentSet:
        for name in names:
            if name not in self._by_name:
                raise errors.COMPARTMENT_MISSING(name=name)
        return CompartmentSet(self._by_name[name] for name in names)


@dataclass
class GroundTruth:
    """Which simulated citizen each presentation, identity record and identifier belongs to.

    ``citizen_rows[c]`` is citizen c's row in the population table. ``domains`` gives each
    presentation's event domain, for completeness.
    """

    citizen_rows: list[int]
    presentations: dict[str, int]
    identities: dict[str, int]
    artifacts: dict[str, int]
    domains: dict[str, str]
    decoys: list[str] = field(default_factory=list)  # identifiers minted for no citizen

    def citizen_of(self, node: str) -> int | None:
        prefix, _, key = node.partition(":")
        table = {"p": self.presentations, "id": self.identities, "x": self.artifacts}.get(prefix)
        if table is None:
            raise errors.NODE_FORMAT(node=node)
        return table.get(key)


@dataclass(frozen=True)
class Join:
    """An attack's assertion that two nodes belong to one citizen, with a confidence in [0, 1].

    A node is ``p:<presentation handle>``, ``id:<identity record>`` or ``x:<identifier>``.
    """

    a: str
    b: str
    confidence: float
    attack: str


@dataclass(frozen=True)
class Observation:
    """An attribute an attack learns about a node without joining it, such as its issuing home."""

    node: str
    attribute: str
    value: str
    attack: str


@dataclass
class Knowledge:
    """Public facts every adversary is assumed to know: the State's policy and its infrastructure.

    It is not ground truth. It says how many copies each citizen receives; how many credentials,
    and so registries and issuance events, one citizen's session creates (`per_citizen`, which
    attacks size their groups by: an issuer may issue two credentials per copy and a retained pair);
    how many issuance anchors that session writes to an issuer's KEL; which issuer AID is which
    home; which addresses belong to verifiers and to the State's own services; and which
    identifiers are the State's public infrastructure (witnesses, schemas, its own parties),
    which link nothing about a citizen.
    """

    copies: int
    per_citizen: int
    issuance_block: int
    issuers: dict[str, str]
    verifier_addresses: dict[str, str]
    service_addresses: list[str]
    infrastructure: list[str] = field(default_factory=list)
