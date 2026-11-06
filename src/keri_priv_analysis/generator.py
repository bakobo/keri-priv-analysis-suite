"""The synthetic generator: an adapter that builds a world from parameters (this.i 8zuzm3v3).

It emits real KEL and TEL bytes with keripy and models every countermeasure in this.i 2gxskju4
as a scenario setting, so designs nobody has built can be scored. Everything it
does not model as protocol bytes (logs, store rows) it writes in the shapes a custodial issuer's
adapter exports, so attacks read both the same way.

The world, in order:
- each issuing home is a keripy issuer with its own KEL;
- each home provisions a pool of registries in a loop, one `rip` anchored per interaction event;
- citizens are issued their copies, in sessions (one citizen's copies a few milliseconds apart)
  or in an order mixed across citizens, each issuance one `upd` or blinded `bup` anchored alone;
- status updates, if any, are anchored per citizen (lockstep) or in batches mixing citizens;
- each registry head is published to the Registrar, at once or at the next publication window;
- citizens present fresh copies to verifiers, and every party's logs are written as they would be.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from math import ceil, floor

import numpy as np
from keri.acdc import messaging
from keri.app import habbing
from keri.core import Counter, Dater, Diger, Number, Salter, SealSource, Signer, eventing
from keri.core.coring import MtrDex
from keri.kering import Kinds, Vrsn_2_0

from .model import (
    Compartment,
    CompartmentSet,
    GroundTruth,
    Knowledge,
    LogLine,
    Presentation,
)
from .population import HOME, Population
from .scenario import ACCESS_LOG_ROLES, Scenario

EPOCH = datetime(2026, 11, 1, tzinfo=UTC)
# The schema SAID every generated credential names. It is a label, not a published schema.
SCHEMA = "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM"
PROVISIONING = -86400.0  # registries are provisioned the day before issuance opens
GVC = bytes(Counter.makeGVC(version=Vrsn_2_0))
SHARED_ADDRESSES = ("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")
AGENT_HOST = "10.200.0.1"
SHARED_AGENTS = 3
UPDATED = "issued"
WITNESS_POOL = 20  # witnesses the State runs for holder AIDs
HOLDER_WITNESSES = 3  # witnesses each holder AID names
CONSTANT_FIRST_SEEN = PROVISIONING - 7200.0


def stamp(t: float, granularity: float) -> str:
    """An RFC 3339 stamp for scenario time t, truncated to the granularity (0: microseconds)."""
    if granularity > 0:
        t = floor(t / granularity) * granularity
    return (EPOCH + timedelta(seconds=t)).isoformat(timespec="microseconds")


@dataclass
class _Registry:
    regid: str
    home: int
    events: list = field(default_factory=list)  # serders, rip first
    citizen: int | None = None  # set when the registry belongs to one citizen
    published: float = 0.0
    said: str = ""  # the credential most recently issued into it


@dataclass
class _Copy:
    citizen: int | None  # None for a decoy
    index: int
    time: float
    home: int
    registry: _Registry | None = None
    said: str = ""
    holder: str = ""
    acdc: bytes = b""


# The scenario settings behind each attack's leak, which the report names as the cause.
CAUSE_SETTINGS = {
    "shared-registry": ("registry_scope",),
    "kel-anchor-adjacency": ("issuance_order", "decoys"),
    "registry-inception-adjacency": ("registry_allocation", "issuance_order"),
    "timestamp-clustering": ("dt_granularity", "issuance_order"),
    "event-count-lockstep": ("status_updates",),
    "shared-batch-root": ("batch_size", "batch_mix"),
    "holder-infrastructure": ("holder_network",),
    "registry-reads": ("holder_status_reads", "holder_network"),
    "hosted-agent": ("hosted_agents",),
    "verifier-probing": ("verifier_probing", "publication_window"),
    "custodial-join": ("sealed_revocation_map", "identity_oracle"),
    "log-scan": ("log_join_material",),
    "holder-kel": ("holder_aids", "holder_witnesses"),
    "payload-invariance": ("copy_template",),
    "shared-holder": ("holder_aids",),
    "agent-end-role": ("hosted_agents", "holder_aids"),
    "shared-anchor": ("anchor_order",),
    "batch-order": ("batch_size", "batch_mix"),
    "kel-first-seen": ("first_seen", "issuance_order"),
    "witness-arrival": ("issuance_order", "holder_witnesses"),
}


class Generator:
    name = "generator"

    def run(self, scenario: Scenario, population: Population):
        return _World(scenario, population).build()

    def provenance(self) -> dict:
        return {"kind": "synthetic", "note": "keripy issuers whose KELs carry no receipts, with "
                "witness arrivals in the witness access log; stores and logs written in the "
                "shapes a custodial issuer's adapter exports"}

    def causes(self, scenario: Scenario) -> dict[str, str]:
        out = {name: "the generator's stack settings " + ", ".join(
            f"{s} = {getattr(scenario.stack, s)!r}" for s in settings)
            for name, settings in CAUSE_SETTINGS.items()}
        out["issuer-aid-bucket"] = (f"{scenario.population.homes} issuing homes assigned "
                                    f"{scenario.population.home_assignment!r}")
        return out


class _World:
    def __init__(self, scenario: Scenario, population: Population):
        self.s = scenario
        self.stack = scenario.stack
        self.pop = population
        self.rng = np.random.default_rng([scenario.run.seed, 2])
        count = scenario.citizens.count
        self.rows = [int(r) for r in self.rng.choice(population.size, size=count, replace=False)]
        self.homes = [int(population.codes[HOME][r]) for r in self.rows]
        self.witness_signers = [Signer(raw=self._bytes(32), transferable=False)
                                for _ in range(WITNESS_POOL)]
        self.witness_pool = [w.verfer.qb64 for w in self.witness_signers]
        # Each citizen's management AID has a KEL, which anchors the holder AIDs it delegates.
        self.smaid_keys, self.smaid_kel, self.smaid = [], [], []
        for _ in range(count):
            signer, serder, message = self._transferable()
            self.smaid_keys.append((signer, serder))
            self.smaid_kel.append([message])
            self.smaid.append(serder.pre)
        self.citizen_witnesses = [self._witnesses() for _ in range(count)]
        self.citizen_nonce = [self._nonce() for _ in range(count)]
        self.citizen_edge = [self._said() for _ in range(count)]
        self.holder_kels: dict[str, bytes] = {}
        # Hosted agents: one per citizen, or a few shared by everyone; each holder AID names its
        # agent in an end-role reply that a verifier resolving it stores.
        self.citizen_agent = [self._aid() for _ in range(count)]
        self.shared_agents = [self._aid() for _ in range(SHARED_AGENTS)]
        self.agent_of: dict[str, str] = {}
        self.citizen_holder: dict[int, str] = {}
        self.device = [f"10.{c // 250}.{c % 250}.7" for c in range(count)]
        self.home_address = [f"10.9.0.{h + 1}" for h in range(population.spec.homes)]
        self.verifier_address = {v: f"198.51.100.{10 + i}"
                                 for i, v in enumerate(scenario.verifiers)}
        self.artifacts: dict[str, int] = {}
        self.decoys: list[str] = []
        self.logs: dict[str, list[LogLine]] = {r: [] for r in ACCESS_LOG_ROLES}
        self.home_logs: dict[int, list[LogLine]] = {h: [] for h in range(population.spec.homes)}
        self.verifier_logs: dict[str, list[LogLine]] = {v: [] for v in scenario.verifiers}

    # Deterministic material, drawn from the run's generator so a seed fixes every byte.

    def _bytes(self, n: int) -> bytes:
        return self.rng.bytes(n)

    def _nonce(self) -> str:
        return Salter(raw=self._bytes(16)).qb64

    def _aid(self) -> str:
        return Signer(raw=self._bytes(32), transferable=False).verfer.qb64

    def _said(self) -> str:
        return Diger(ser=self._bytes(32)).qb64

    def _witnesses(self) -> list[str]:
        picks = self.rng.choice(WITNESS_POOL, size=HOLDER_WITNESSES, replace=False)
        return [self.witness_pool[int(i)] for i in sorted(picks)]

    def _transferable(self, witnesses=(), delegator=None):
        """A transferable AID's inception, signed by its key and receipted by its witnesses: the
        signer, the serder and the message bytes. A delegated inception names its delegator and
        carries the seal source of the delegator's event that anchors it."""
        signer = Signer(raw=self._bytes(32), transferable=True)
        following = Signer(raw=self._bytes(32), transferable=True)
        kwa = {"keys": [signer.verfer.qb64], "ndigs": [Diger(ser=following.verfer.qb64b).qb64],
               "wits": list(witnesses), "toad": len(witnesses), "code": MtrDex.Blake3_256,
               "kind": Kinds.json}
        serder = (eventing.delcept(delpre=self.smaid[delegator], **kwa) if delegator is not None
                  else eventing.incept(**kwa))
        wigers = [self.witness_signers[self.witness_pool.index(w)].sign(serder.raw, index=i)
                  for i, w in enumerate(witnesses)]
        bonds = None
        if delegator is not None:
            anchor = self._delegate(delegator, serder)
            bonds = [SealSource(s=Number(num=int(anchor.sad["s"], 16)), d=Diger(qb64=anchor.said))]
        message = eventing.messagize(serder, sigers=[signer.sign(serder.raw, index=0)],
                                     wigers=wigers or None, bonds=bonds)
        return signer, serder, bytes(message)

    def _delegate(self, citizen: int, delegated):
        """Anchor a delegated inception in the citizen's management AID's KEL."""
        signer, last = self.smaid_keys[citizen]
        ixn = eventing.interact(last.pre, last.said, sn=int(last.sad["s"], 16) + 1,
                                data=[{"i": delegated.pre, "s": "0", "d": delegated.said}],
                                kind=Kinds.json)
        self.smaid_keys[citizen] = (signer, ixn)
        self.smaid_kel[citizen].append(bytes(eventing.messagize(
            ixn, sigers=[signer.sign(ixn.raw, index=0)])))
        return ixn

    def _holder(self, citizen: int) -> str:
        """A fresh holder AID for one copy, and its KEL when it has one; or, when holder AIDs are
        shared, the citizen's one AID for every copy."""
        if self.stack.holder_aids == "shared" and citizen in self.citizen_holder:
            return self.citizen_holder[citizen]
        if self.stack.holder_aids == "nontransferable":
            return self._aid()
        witnesses = (self.citizen_witnesses[citizen]
                     if self.stack.holder_witnesses == "per-citizen" else self._witnesses())
        delegator = citizen if self.stack.holder_aids == "delegated" else None
        _, serder, message = self._transferable(witnesses, delegator)
        # What a verifier resolves for this holder AID: the delegator's KEL up to the event
        # anchoring it, when delegated, then the holder's own inception.
        prefix = b"".join(self.smaid_kel[citizen]) if delegator is not None else b""
        self.holder_kels[serder.pre] = prefix + message
        self.citizen_holder[citizen] = serder.pre
        return serder.pre

    def _holder_source(self, citizen: int) -> str:
        if self.stack.holder_network == "direct":
            return self.device[citizen]
        return SHARED_ADDRESSES[int(self.rng.integers(len(SHARED_ADDRESSES)))]

    # The build.

    def build(self):
        salt = Salter(raw=hashlib.sha256(f"kpa-{self.s.run.seed}".encode()).digest()[:16]).qb64
        with habbing.openHby(name=f"kpa-gen-{self.s.run.seed}", temp=True, salt=salt) as hby:
            self.habs = [hby.makeHab(name=f"home-{h}", isith="1", icount=1, nsith="1", ncount=1,
                                     toad=0) for h in range(self.pop.spec.homes)]
            for hab in self.habs:
                self._first_seen(hab, PROVISIONING - 3600.0)
            copies = self._schedule()
            self._provision(copies)
            self._issue(copies)
            self._update()
            self._publish()
            presentations = self._present(copies)
            kels = {hab.pre: b"".join(bytes(m) for m in hab.db.clonePreIter(pre=hab.pre))
                    for hab in self.habs}
        return self._export(copies, presentations, kels)

    def _schedule(self) -> list[_Copy]:
        c = self.s.citizens
        copies = []
        if self.stack.issuance_order == "per-citizen":
            starts = np.sort(self.rng.uniform(0, c.issuance_period, size=c.count))
            for citizen, start in enumerate(starts):
                copies += [_Copy(citizen, j, float(start) + j * c.copy_interval,
                                 self.homes[citizen]) for j in range(c.copies)]
        else:
            for citizen in range(c.count):
                copies += [_Copy(citizen, j, float(t), self.homes[citizen])
                           for j, t in enumerate(self.rng.uniform(0, c.issuance_period,
                                                                  size=c.copies))]
        for _ in range(self.stack.decoys):
            copies.append(_Copy(None, 0, float(self.rng.uniform(0, c.issuance_period)),
                                int(self.rng.integers(self.pop.spec.homes))))
        copies.sort(key=lambda x: x.time)
        return copies

    def _first_seen(self, hab, t: float) -> None:
        """Pin the first-seen time keripy records for the issuer's latest event to scenario time.

        keripy stamps it from the wall clock and replays it with the KEL, so leaving it would make
        the bytes differ run to run. Pinned to the simulated clock, it also models what a real
        issuer's KEL replay discloses: when each of its events happened, to the microsecond.
        """
        when = t if self.stack.first_seen == "exact" else CONSTANT_FIRST_SEEN
        hab.db.dtss.pin(keys=(hab.pre, hab.kever.serder.said), val=Dater(dts=stamp(when, 0)))
        # The State's witnesses receipt the event as it arrives. The KEL bytes are witnessless;
        # the access log records the arrival a deployed witness would see.
        self.logs["witness"].append(LogLine(t + float(self.rng.uniform(0.001, 0.05)),
                                            self.home_address[self.habs.index(hab)],
                                            f"POST /receipts {hab.kever.serder.said}"))

    def _anchor(self, home: int, seals: list[dict], t: float) -> None:
        hab = self.habs[home]
        hab.interact(data=seals)
        self._first_seen(hab, t)

    def _incept(self, home: int, t: float) -> _Registry:
        hab = self.habs[home]
        rip = messaging.regcept(hab.pre, uuid=self._nonce(),
                                stamp=stamp(t, self.stack.dt_granularity))
        self._anchor(home, [{"i": rip.said, "s": rip.sad["n"], "d": rip.said}], t)
        self.home_logs[home].append(LogLine(t, self.home_address[home],
                                            f"provisioned registry {rip.said}"))
        return _Registry(regid=rip.said, home=home, events=[rip])

    def _provision(self, copies: list[_Copy]) -> None:
        """Incept each home's pool in a loop, then allocate registries in issuance order."""
        scope = self.stack.registry_scope
        need = {h: 0 for h in range(len(self.habs))}
        if scope == "issuer":
            need = dict.fromkeys(need, 1)
        else:
            seen = set()
            for copy in copies:
                if scope == "credential" or copy.citizen is None or copy.citizen not in seen:
                    need[copy.home] += 1
                    seen.add(copy.citizen)
        pools = {h: [self._incept(h, PROVISIONING + i * 0.01) for i in range(n)]
                 for h, n in need.items()}
        self.registries = [r for pool in pools.values() for r in pool]
        by_citizen: dict[int, _Registry] = {}
        for copy in copies:
            pool = pools[copy.home]
            if scope == "issuer":
                copy.registry = pool[0]
                continue
            if scope == "citizen" and copy.citizen is not None and copy.citizen in by_citizen:
                copy.registry = by_citizen[copy.citizen]
                continue
            pick = 0 if self.stack.registry_allocation == "fifo" else int(
                self.rng.integers(len(pool)))
            copy.registry = pool.pop(pick)
            copy.registry.citizen = copy.citizen
            if copy.citizen is not None:
                by_citizen[copy.citizen] = copy.registry
                self.artifacts[copy.registry.regid] = copy.citizen

    def _tel_event(self, registry: _Registry, said: str, t: float):
        prior = registry.events[-1]
        sn = len(registry.events)
        when = stamp(t, self.stack.dt_granularity)
        if self.stack.tel_updates == "bup":
            event = messaging.blindate(registry.regid, prior.said, self._said(), sn=sn, stamp=when)
        else:
            event = messaging.update(registry.regid, prior.said, said, UPDATED, sn=sn, stamp=when)
        registry.events.append(event)
        return {"i": registry.regid, "s": event.sad["n"], "d": event.said}

    def _attributes(self, copy: _Copy) -> dict:
        if self.stack.copy_template == "cloned-attributes" and copy.citizen is not None:
            return {"d": "", "u": self.citizen_nonce[copy.citizen]}
        return {"d": "", "u": self._nonce(), "i": copy.holder}

    def _edge(self, copy: _Copy) -> dict | None:
        if self.stack.copy_template != "shared-edge" or copy.citizen is None:
            return None
        return {"d": "", "identity": {"n": self.citizen_edge[copy.citizen], "s": SCHEMA}}

    def _issue(self, copies: list[_Copy]) -> None:
        pending = []
        for copy in copies:
            hab = self.habs[copy.home]
            copy.holder = self._aid() if copy.citizen is None else self._holder(copy.citizen)
            acdc = messaging.acdcmap(hab.pre, uuid=self._nonce(), regid=copy.registry.regid,
                                     schema=SCHEMA, attribute=self._attributes(copy),
                                     edge=self._edge(copy), compactify=True)
            copy.said, copy.acdc = acdc.said, bytes(acdc.raw)
            copy.registry.said = copy.said
            pending.append((copy.home, self._tel_event(copy.registry, copy.said, copy.time)))
            if copy.citizen is None:
                self.decoys += [copy.said, copy.holder]
                continue
            for identifier in (copy.said, copy.holder):
                self.artifacts[identifier] = copy.citizen
            self._holder_traffic(copy)
        order = self.stack.anchor_order
        if order == "issuance":
            groups = [[(home, seal)] for home, seal in pending]
            times = [copy.time for copy in copies]
        elif order == "per-citizen":
            # One interaction event seals all of a citizen's issuances, when its session opens.
            by_citizen: dict = {}
            for (home, seal), copy in zip(pending, copies, strict=True):
                key = copy.citizen if copy.citizen is not None else ("decoy", seal["d"])
                by_citizen.setdefault(key, ([], copy.time))[0].append((home, seal))
            groups = [g for g, _ in by_citizen.values()]
            times = [t for _, t in by_citizen.values()]
        else:
            # Stamped as issued and anchored later, in an order mixed across citizens, as an
            # asynchronous issuer draining a shuffled queue would: one seal per event, or
            # batches of one citizen's copy count drawn across citizens.
            shuffled = [pending[int(i)] for i in self.rng.permutation(len(pending))]
            size = self.s.citizens.copies if order == "batched" else 1
            groups = [shuffled[i:i + size] for i in range(0, len(shuffled), size)]
            times = sorted(float(t) for t in self.rng.uniform(0, self.s.citizens.issuance_period,
                                                              size=len(groups)))
        for group, t in zip(groups, times, strict=True):
            by_home: dict[int, list[dict]] = {}
            for home, seal in group:
                by_home.setdefault(home, []).append(seal)
            for home, seals in by_home.items():
                self._anchor(home, seals, t)
        self.copies = copies

    def _holder_traffic(self, copy: _Copy) -> None:
        """The holder device admits the copy: it registers the copy's AID with a mailbox and a
        witness, and a hosted agent, if any, serves the AID."""
        t = copy.time + 1.0  # within the scenario's ADMISSION window
        source = self._holder_source(copy.citizen)
        self.logs["mailbox"].append(LogLine(t, source, f"PUT /mailbox/{copy.holder}"))
        self.logs["holder-witness"].append(LogLine(t, source, f"POST /oobi/{copy.holder}"))
        if self.stack.hosted_agents == "none":
            return
        if self.stack.hosted_agents == "per-citizen":
            agent = self.citizen_agent[copy.citizen]
        else:
            agent = self.shared_agents[int(self.rng.integers(SHARED_AGENTS))]
        self.agent_of[copy.holder] = agent
        self.logs["hosted-agent"].append(LogLine(t, AGENT_HOST, f"agent {agent} serves "
                                                 f"{copy.holder}"))

    def _update(self) -> None:
        """Status updates: one anchor per citizen over all its registries, or batches that mix."""
        if self.stack.status_updates == "none":
            return
        real = [r for r in self.registries if r.citizen is not None]
        period = self.s.citizens.issuance_period
        if self.stack.status_updates == "lockstep":
            groups = {}
            for registry in real:
                groups.setdefault(registry.citizen, []).append(registry)
            batches = list(groups.values())
        else:
            order = [real[int(i)] for i in self.rng.permutation(len(real))]
            size = self.s.citizens.copies
            batches = [order[i:i + size] for i in range(0, len(order), size)]
        for batch in batches:
            t = period + float(self.rng.uniform(0, period))
            by_home: dict[int, list[dict]] = {}
            for registry in batch:
                seal = self._tel_event(registry, registry.said, t)
                by_home.setdefault(registry.home, []).append(seal)
            for home, seals in by_home.items():
                self._anchor(home, seals, t)

    def _publish(self) -> None:
        window = self.stack.publication_window
        issued = {}
        for copy in self.copies:
            issued[copy.registry.regid] = max(issued.get(copy.registry.regid, 0.0), copy.time)
        for registry in self.registries:
            t = issued.get(registry.regid, PROVISIONING)
            registry.published = ceil(t / window) * window if window > 0 else t
            source = self.home_address[registry.home]
            self.logs["registrar"].append(LogLine(
                registry.published, source, f"POST /v1/registrar/publication {registry.regid}"))
            self.home_logs[registry.home].append(LogLine(
                registry.published, source, f"published registry {registry.regid}"))
            if self.stack.verifier_probing:
                for v, address in self.verifier_address.items():
                    self.verifier_logs[v].append(LogLine(
                        registry.published + 0.5, address, f"first-seen {registry.regid}"))
        self.batches = []
        if self.stack.batch_size > 0:
            if self.stack.batch_mix == "citizen":
                groups = {}
                for r in self.registries:
                    groups.setdefault(r.citizen if r.citizen is not None else r.regid,
                                      []).append(r.regid)
                self.batches = list(groups.values())
            else:
                if self.stack.batch_mix == "ordered":
                    order = [r.regid for r in sorted(self.registries, key=lambda r: (
                        issued.get(r.regid, PROVISIONING), r.regid))]
                else:
                    order = [self.registries[int(i)].regid
                             for i in self.rng.permutation(len(self.registries))]
                size = self.stack.batch_size
                self.batches = [order[i:i + size] for i in range(0, len(order), size)]

    def _present(self, copies: list[_Copy]) -> list[tuple[Presentation, int]]:
        own: dict[int, list[_Copy]] = {}
        for copy in copies:
            if copy.citizen is not None:
                own.setdefault(copy.citizen, []).append(copy)
        out = []
        for citizen in range(self.s.citizens.count):
            row = self.pop.row(self.rows[citizen])
            wallet = [own[citizen][int(i)] for i in self.rng.permutation(len(own[citizen]))]
            for plan in self.s.presentations:
                for _ in range(plan.per_citizen):
                    copy = wallet.pop()
                    # The scenario loader holds windows to open after the last copy is issued.
                    t = float(self.rng.uniform(plan.start, plan.end))
                    tel = GVC + b"".join(bytes(e.raw) for e in copy.registry.events)
                    p = Presentation(
                        handle=self._bytes(8).hex(), verifier=plan.verifier, time=t,
                        domain=plan.domain, disclosed={a: row[a] for a in plan.disclose},
                        said=copy.said, registry=copy.registry.regid,
                        issuer=self.habs[copy.home].pre, holder=copy.holder,
                        raw=GVC + copy.acdc + tel)
                    out.append((p, citizen))
                    self.logs["observer"].append(LogLine(
                        t + 0.2, self.verifier_address[plan.verifier],
                        f"GET /registry/{copy.registry.regid}"))
            if self.stack.holder_status_reads:
                for copy in own[citizen]:
                    for _ in range(2):
                        t = float(self.rng.uniform(copy.time, self.s.citizens.issuance_period * 2))
                        self.logs["observer"].append(LogLine(
                            t, self._holder_source(citizen), f"GET /registry/{copy.registry.regid}"))
        return out

    def _records(self, home: int) -> dict[str, list[dict[str, str]]]:
        rows, identities = [], []
        for copy in self.copies:
            if copy.home != home:
                continue
            row = {"registry": copy.registry.regid, "said": copy.said, "holder": copy.holder,
                   "state": "issued", "time": repr(copy.time)}
            if not self.stack.sealed_revocation_map:
                if copy.citizen is None:
                    row["management"] = self._aid()
                    self.decoys.append(row["management"])
                elif self.stack.identity_oracle:
                    row["management"] = self._cryptonym("home", home, copy.citizen)
                else:
                    row["management"] = self.smaid[copy.citizen]
            rows.append(row)
            if copy.citizen is not None and not self.stack.identity_oracle:
                # The baseline models the clear credential copies a custodial issuing home retains.
                # The name is synthetic, while the credential SAID and management AID are real
                # artifacts from this generated run. Sealing only the revocation map does not
                # remove the home's retained named credential (this.i 7wwc4pdd).
                identities.append({"record": copy.said, "said": copy.said,
                                   "management": self.smaid[copy.citizen],
                                   "givenName": f"Citizen{copy.citizen}",
                                   "familyName": "Synthetic", "time": repr(copy.time)})
        return {"pool": rows, "identities": identities}

    def _cryptonym(self, *parts) -> str:
        token = "C" + hashlib.sha256(repr((self.s.run.seed, *parts)).encode()).hexdigest()[:43]
        self.artifacts[token] = parts[-1]
        return token

    def _export(self, copies, presentations, kels):
        count = self.s.citizens.count
        for c in range(count):
            self.artifacts[self.smaid[c]] = c
            self.artifacts[self.citizen_agent[c]] = c
        streams = {f"kel:{pre}": kel for pre, kel in kels.items()}
        for r in self.registries:
            streams[f"tel:{r.regid}"] = GVC + b"".join(bytes(e.raw) for e in r.events)
        for n, batch in enumerate(self.batches):
            root = hashlib.sha256("".join(sorted(batch)).encode()).hexdigest()
            streams[f"batch:{n}"] = json.dumps({"root": root, "registries": batch}).encode()

        compartments = [Compartment(name="public", status="present", streams=streams)]
        for v in self.s.verifiers:
            held = [p for p, _ in presentations if p.verifier == v]
            roles = sorted({p.holder for p in held if p.holder in self.agent_of})
            compartments.append(Compartment(
                name=f"verifier:{v}", status="present", presentations=held,
                records={"end-roles": [{"aid": h, "role": "agent", "eid": self.agent_of[h]}
                                       for h in roles]} if roles else {},
                streams={f"kel:{p.holder}": self.holder_kels[p.holder] for p in held
                         if p.holder in self.holder_kels},
                logs=self.verifier_logs[v]))
        for h in range(len(self.habs)):
            compartments.append(Compartment(name=f"issuing-home:{h}", status="present",
                                            records=self._records(h), logs=self._home_log(h)))
        identities = {row["record"]: self.artifacts[row["record"]]
                      for compartment in compartments if compartment.kind == "issuing-home"
                      for row in compartment.records["identities"]}
        idp_rows, revocations = [], []
        for c in range(count):
            record = f"iar-{self._bytes(6).hex()}"
            identities[record] = c
            key = (self._cryptonym("idp", c) if self.stack.identity_oracle else self.smaid[c])
            idp_rows.append({"record": record, "management": key, **self.pop.row(self.rows[c])})
        for copy in self.copies:
            if copy.citizen is None:
                continue
            if self.stack.sealed_revocation_map:
                revocations.append({"sealed": self._bytes(32).hex()})
            else:
                revocations.append({"said": copy.said, "management": self.smaid[copy.citizen]})
        compartments += [
            Compartment(name="identity-proofing", status="present", records={"iar": idp_rows}),
            Compartment(name="revocation-authority", status="present",
                        records={"revocation": revocations}),
            Compartment(name="orchestrator", status="absent",
                        note="The generator models no orchestrator."),
            # ~5d76: model an asynchronous issuer's durable rows before using this channel in sweeps.
            Compartment(name="operation-log", status="absent",
                        note="The generator models no asynchronous operation log."),
        ]
        for role in ACCESS_LOG_ROLES:
            name = f"access-log:{role}"
            if role == "watcher":
                compartments.append(Compartment(name=name, status="absent",
                                                note="The generator models no watchers."))
            elif role == "hosted-agent" and self.stack.hosted_agents == "none":
                compartments.append(Compartment(name=name, status="absent",
                                                note="No hosted agents in this configuration."))
            else:
                compartments.append(Compartment(name=name, status="present",
                                                logs=sorted(self.logs[role],
                                                            key=lambda x: x.time)))

        truth = GroundTruth(
            citizen_rows=self.rows,
            presentations={p.handle: c for p, c in presentations},
            identities=identities,
            artifacts=self.artifacts,
            domains={p.handle: p.domain for p, _ in presentations},
            decoys=self.decoys,
        )
        issuance_block = self.s.citizens.copies
        knowledge = Knowledge(
            copies=self.s.citizens.copies,
            per_citizen=self.s.citizens.copies,
            issuance_block=issuance_block,
            issuers={hab.pre: str(h) for h, hab in enumerate(self.habs)},
            verifier_addresses={a: v for v, a in self.verifier_address.items()},
            service_addresses=list(self.home_address) + [AGENT_HOST],
            infrastructure=[SCHEMA, *self.witness_pool, *self.shared_agents],
        )
        return CompartmentSet(compartments), truth, knowledge

    def _home_log(self, home: int) -> list[LogLine]:
        """The home's application log. With join material planted, half the citizens' sessions
        are logged on one line naming every identifier, and half as a trace whose lines each
        name one identifier and share a trace id."""
        lines = list(self.home_logs[home])
        if self.stack.log_join_material:
            traces = {}
            for copy in self.copies:
                if copy.home != home or copy.citizen is None:
                    continue
                source = self.home_address[home]
                if copy.citizen % 2 == 0:
                    lines.append(LogLine(
                        copy.time, source,
                        f"bulk issuance for {self.smaid[copy.citizen]}: registry "
                        f"{copy.registry.regid} credential {copy.said} to {copy.holder}"))
                    continue
                if copy.citizen not in traces:
                    traces[copy.citizen] = self._bytes(8).hex()
                    lines.append(LogLine(copy.time, source,
                                         f"[trace={traces[copy.citizen]}] bulk issuance for "
                                         f"{self.smaid[copy.citizen]}"))
                lines.append(LogLine(copy.time, source,
                                     f"[trace={traces[copy.citizen]}] issued credential "
                                     f"{copy.said}"))
        return sorted(lines, key=lambda x: x.time)
