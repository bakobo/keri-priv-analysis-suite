"""Drive a scenario's issuance and presentation through KERIA agents with SignifyPy.

The adapter hands over a plan (who the citizens are, which home issues to each, the order of
issuance and of presentations), and the driver performs it as KERIA's ordinary usage would:

- each issuing home is one KERIA agency hosting one issuer agent, whose AID incepts one registry;
- the citizens' hosted agents live on one wallet agency, one agent per citizen, and each copy a
  citizen holds is issued to a fresh AID in that citizen's agent;
- each verifier is its own agency with one agent;
- the issuer issues each copy and sends it by IPEX grant, the holder admits it; later the holder
  presents a copy by IPEX grant to a verifier, which admits it.

AIDs are witnessless, so no witness runs. Every action records the wall-clock time it started, so
the adapter can place it, and the log lines around it, at the scenario's time.
"""

from __future__ import annotations

import hashlib
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import requests
from keri.app import signing as app_signing
from keri.core import coring, eventing
from keri.core import signing as csigning
from keri.core.coring import Tiers
from keri.core.signing import Salter
from keri.help import helping
from requests import HTTPError
from signify.app.clienting import SignifyClient

from . import errors, schema
from .host import Host

POLL = 0.1
TIMEOUT = 300.0
SETUP_WORKERS = 4
BOOT_ATTEMPTS = 100
REGISTRY = "registry"
ISSUER = "issuer"
VERIFIER = "verifier"
PLAN_KEYS = ("seed", "homes", "verifiers", "attributes", "citizens", "copies", "issuance",
             "presentations", "dt_granularity")
ALPHABET = string.ascii_lowercase + string.digits


def secret(seed: int, *parts) -> str:
    """A 21-character passcode or nonce fixed by the run's seed, so AIDs repeat run to run."""
    digest = hashlib.sha256(repr((seed, *parts)).encode()).digest()
    return "".join(ALPHABET[b % len(ALPHABET)] for b in digest[:21])


def alias(seed: int, *parts) -> str:
    """A neutral name for an AID, which says nothing about whose it is."""
    return "aid-" + hashlib.sha256(repr((seed, "alias", *parts)).encode()).hexdigest()[:12]


def stamp(granularity: float) -> str:
    """The issuance timestamp a Signify client sends: now, truncated to the granularity."""
    now = helping.nowUTC()
    if granularity > 0:
        now = now.fromtimestamp(now.timestamp() // granularity * granularity, tz=now.tzinfo)
    return helping.toIso8601(now)


def until(fetch, what: str, timeout: float = TIMEOUT):
    """Call fetch until it returns something other than None, treating an HTTP error as not yet."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            got = fetch()
        except HTTPError:
            got = None
        if got is not None:
            return got
        if time.monotonic() > deadline:
            raise errors.WAIT_TIMEOUT(what=what, seconds=timeout)
        time.sleep(POLL)


class Party:
    """One Signify controller and the KERIA agent it boots on a host."""

    def __init__(self, host: Host, passcode: str):
        self.host = host
        attempt = 0
        while True:
            self.client = SignifyClient(passcode=passcode, tier=Tiers.low, url=host.admin_url,
                                        boot_url=host.boot_url)
            try:
                self.client.boot()
                break
            except requests.ConnectionError:
                # The boot port can accept before the agency's loop serves it.
                attempt += 1
                if attempt == BOOT_ATTEMPTS:
                    raise
                time.sleep(0.2)
        self.client.connect()
        self.agent = self.client.agent.pre
        self.controller = self.client.ctrl.pre

    def wait(self, operation: dict) -> dict:
        return self.client.operations().wait(operation, timeout=TIMEOUT, interval=POLL,
                                             max_interval=POLL, backoff=1.0)

    def incept(self, name: str, bran: str) -> str:
        """A witnessless AID whose key salt is `bran`, so one seed gives the same AID."""
        _, _, op = self.client.identifiers().create(name, toad="0", wits=[], bran=bran)
        self.wait(op)
        _, _, op = self.client.identifiers().addEndRole(name=name, eid=self.agent)
        self.wait(op)
        return self.client.identifiers().get(name)["prefix"]

    def oobi(self, name: str) -> str:
        return until(lambda: (self.client.oobis().get(name, role="agent")["oobis"] or [None])[0],
                     f"the agent OOBI of {name}")

    def resolve(self, url: str, name: str) -> None:
        self.wait(self.client.oobis().resolve(url, alias=name))

    def exchange(self, said: str, what: str) -> dict:
        return until(lambda: self.client.exchanges().get(said), what)

    def credential(self, said: str, what: str) -> dict:
        return until(lambda: self.client.credentials().get(said), what)


@dataclass
class Citizen:
    party: Party
    holders: list[str]  # one AID per copy
    names: list[str]
    knows_issuer: bool = False
    knows: set = field(default_factory=set)  # verifiers whose OOBI the agent resolved


class World:
    """The parties of one run and what they did, in the order they did it."""

    def __init__(self, plan: dict, hosts: dict[str, Host], schema_said: str):
        self.plan = plan
        self.hosts = hosts
        self.schema = schema_said
        self.seed = plan["seed"]
        self.timeline: list[tuple[str, int, float]] = []
        self.issuers: list[dict] = []
        self.verifiers: dict[str, dict] = {}
        self.citizens: list[Citizen] = []
        self.credentials: list[dict] = []
        self.presented: list[dict] = []

    def _start(self, kind: str, n: int) -> None:
        """Record an action's start, in a wall-clock second of its own: KERIA stamps its log
        lines to the second, and two actions starting in one second could not be told apart
        when the adapter places those lines on the scenario's clock. A clock that stepped back
        is refused, since lines stamped after the step would fall under an earlier action."""
        now = time.time()
        while self.timeline and int(now) <= int(last := self.timeline[-1][2]):
            if now < last:
                raise errors.CLOCK_STEPPED(now=now, last=last)
            time.sleep(int(last) + 1 - now)
            now = time.time()
        self.timeline.append((kind, n, now))

    def provision(self) -> None:
        """Incept each home's issuer and registry, each verifier, and each citizen's agent and
        holder AIDs, then have each home learn its own citizens' holder AIDs."""
        self._start("provision", -1)
        for h in range(self.plan["homes"]):
            party = Party(self.hosts[f"home-{h}"], secret(self.seed, "home", h))
            aid = party.incept(ISSUER, secret(self.seed, "issuer-aid", h))
            result = party.client.registries().create(ISSUER, REGISTRY,
                                                      nonce=self._nonce("registry", h))
            party.wait(result.op())
            regk = party.client.registries().get(ISSUER, REGISTRY)["regk"]
            self.issuers.append({"party": party, "aid": aid, "registry": regk,
                                 "oobi": party.oobi(ISSUER), "lock": threading.Lock()})
        for v in self.plan["verifiers"]:
            party = Party(self.hosts[f"verifier-{v}"], secret(self.seed, "verifier", v))
            self.verifiers[v] = {"party": party,
                                 "aid": party.incept(VERIFIER, secret(self.seed, "verifier-aid", v)),
                                 "oobi": party.oobi(VERIFIER)}
        with ThreadPoolExecutor(SETUP_WORKERS) as pool:
            self.citizens = list(pool.map(self._citizen, range(len(self.plan["citizens"]))))

    def _nonce(self, *parts) -> str:
        return Salter(raw=hashlib.sha256(repr((self.seed, *parts)).encode())
                             .digest()[:16]).qb64

    def _citizen(self, c: int) -> Citizen:
        party = Party(self.hosts["wallet"], secret(self.seed, "citizen", c))
        names = [alias(self.seed, c, j) for j in range(self.plan["copies"])]
        holders = [party.incept(name, secret(self.seed, "holder-aid", c, j))
                   for j, name in enumerate(names)]
        issuer = self.issuers[self.plan["citizens"][c]["home"]]
        with issuer["lock"]:  # one Signify client is not shared across threads
            for name in names:
                issuer["party"].resolve(party.oobi(name), name)
        return Citizen(party=party, holders=holders, names=names)

    def issue(self) -> None:
        for n, step in enumerate(self.plan["issuance"]):
            self._start("issue", n)
            self.credentials.append(self._issue(step["citizen"], step["copy"]))

    def _issue(self, c: int, j: int) -> dict:
        citizen = self.citizens[c]
        home = self.plan["citizens"][c]["home"]
        issuer = self.issuers[home]
        party = issuer["party"]
        if not citizen.knows_issuer:
            citizen.party.resolve(issuer["oobi"], ISSUER)
            citizen.knows_issuer = True
        holder = citizen.holders[j]
        data = {"i": holder, **self.plan["citizens"][c]["attributes"]}
        result = party.client.credentials().issue(
            ISSUER, REGISTRY, data=data, schema=self.schema, recipient=holder,
            timestamp=stamp(self.plan["dt_granularity"]))
        party.wait(result.op())
        acdc = app_signing.serialize(result.acdc, coring.Prefixer(qb64=result.iss.pre),
                                     coring.Seqner(sn=result.iss.sn),
                                     coring.Saider(qb64=result.iss.said))
        anc = eventing.messagize(serder=result.anc,
                                 sigers=[csigning.Siger(qb64=s) for s in result.sigs])
        grant, sigs, atc = party.client.ipex().grant(
            party.client.identifiers().get(ISSUER), recp=holder, message="", acdc=acdc,
            iss=party.client.registries().serialize(result.iss, result.anc), anc=anc,
            dt=helping.nowIso8601())
        party.wait(party.client.ipex().submitGrant(ISSUER, exn=grant, sigs=sigs, atc=atc,
                                                   recp=[holder]))
        citizen.party.exchange(grant.said, f"the grant of {result.acdc.said} at its holder")
        admit, sigs, atc = citizen.party.client.ipex().admit(
            citizen.party.client.identifiers().get(citizen.names[j]), "", grant.said,
            issuer["aid"], helping.nowIso8601())
        citizen.party.wait(citizen.party.client.ipex().submitAdmit(
            citizen.names[j], exn=admit, sigs=sigs, atc=atc, recp=[issuer["aid"]]))
        party.exchange(admit.said, f"the admit of {result.acdc.said} at its issuer")
        return {"citizen": c, "copy": j, "said": result.acdc.said, "registry": issuer["registry"],
                "issuer": issuer["aid"], "holder": holder, "home": home}

    def present(self) -> None:
        held = {(cred["citizen"], cred["copy"]): cred for cred in self.credentials}
        for n, step in enumerate(self.plan["presentations"]):
            self._start("present", n)
            self.presented.append(self._present(held[(step["citizen"], step["copy"])],
                                                step["verifier"]))

    def _present(self, cred: dict, v: str) -> dict:
        citizen = self.citizens[cred["citizen"]]
        verifier = self.verifiers[v]
        name = citizen.names[cred["copy"]]
        verifier["party"].resolve(citizen.party.oobi(name), name)
        if v not in citizen.knows:
            citizen.party.resolve(verifier["oobi"], v)
            citizen.knows.add(v)
        stored = citizen.party.credential(cred["said"], f"credential {cred['said']} at its holder")
        client = citizen.party.client
        grant, sigs, atc = client.ipex().grant(
            name=name, recipient=verifier["aid"], acdc=stored["sad"], iss=stored["iss"],
            anc=stored["anc"], acdcAttachment=stored.get("atc"),
            issAttachment=stored.get("issatc"), ancAttachment=stored.get("ancatc"),
            dt=helping.nowIso8601())
        citizen.party.wait(client.ipex().submitGrant(name, grant, sigs, atc, [verifier["aid"]]))
        vclient = verifier["party"].client
        verifier["party"].exchange(grant.said, f"the presentation of {cred['said']} at {v}")
        admit, sigs, atc = vclient.ipex().admit(name=VERIFIER, recipient=cred["holder"],
                                                grantSaid=grant.said, dt=helping.nowIso8601())
        verifier["party"].wait(vclient.ipex().submitAdmit(VERIFIER, admit, sigs, atc,
                                                          [cred["holder"]]))
        verifier["party"].credential(cred["said"], f"credential {cred['said']} at {v}")
        return {**cred, "verifier": v, "grant": grant.said}


def check_plan(plan: dict) -> None:
    for key in PLAN_KEYS:
        if key not in plan:
            raise errors.PLAN_FORMAT(key=key)


def hosts_for(plan: dict, work: Path, durls: list[str]) -> dict[str, Host]:
    names = ([f"home-{h}" for h in range(plan["homes"])] + ["wallet"]
             + [f"verifier-{v}" for v in plan["verifiers"]])
    return {name: Host(name, work, durls) for name in names}


def run(plan: dict, work: Path) -> dict:
    """Perform the plan on fresh KERIA agencies under `work`, stopping every agency it started."""
    from . import exporting

    check_plan(plan)
    work = Path(work)
    built = schema.build(plan["attributes"])
    with schema.Server(built) as server:
        hosts = hosts_for(plan, work, [server.oobi])
        try:
            for host in hosts.values():
                host.start()
            for host in hosts.values():
                host.wait_ready()
            world = World(plan, hosts, server.said)
            world.provision()
            world.issue()
            world.present()
        finally:
            for host in hosts.values():
                host.stop()
    return exporting.export(world, hosts)
