"""The scenario file: everything a run depends on, with nothing left to a default.

docs/test-plan.md, 'Scenarios'. A scenario is TOML. Every parameter must be present, any key the
suite does not know is refused, and the run's identity is the SHA-256 of the file's bytes.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from math import isnan
from pathlib import Path

from . import errors
from .model import KINDS, SINGLE_KINDS, parse_compartment_name
from .population import Attribute, Correlation, PopulationSpec

MAX_BYTES = 1024 * 1024
ADAPTERS = ("generator", "keria")
PARTY_KINDS = ("colluding-verifier", "hacker", "insider", "government", "network-observer")
ACCESS_LOG_ROLES = ("witness", "registrar", "observer", "watcher", "holder-witness", "mailbox",
                    "hosted-agent")
METRICS = ("reidentified", "max_bits", "median_bits", "precision", "certain_share",
           "flagged_domains", "max_increment", "identity_exposed", "breach_reidentified")
OPS = ("<=", ">=", "<", ">", "==")

# Each field: (type, allowed values or None). Types: int, float, str, bool, strs, floats.
_RUN = {"seed": ("int", None), "adapter": ("str", ADAPTERS), "confidence_cut": ("float", None)}
_POPULATION = {"size": ("int", None), "seed": ("int", None), "homes": ("int", None),
               "home_assignment": ("str", None), "attribute": ("tables", None),
               "correlation": ("tables", None)}
_ATTRIBUTE = {"name": ("str", None), "values": ("strs", None), "probabilities": ("floats", None),
              "sensitive": ("bool", None)}
_CORRELATION = {"a": ("str", None), "b": ("str", None), "rho": ("float", None)}
_CITIZENS = {"count": ("int", None), "copies": ("int", None), "issuance_period": ("float", None),
             "copy_interval": ("float", None)}
_DOMAIN = {"name": ("str", None), "mandatory": ("bool", None)}
_VERIFIER = {"id": ("str", None)}
_PRESENTATION = {"verifier": ("str", None), "domain": ("str", None), "disclose": ("strs", None),
                 "per_citizen": ("int", None), "start": ("float", None), "end": ("float", None)}
_STACK = {
    "registry_scope": ("str", ("credential", "citizen", "issuer")),
    "registry_allocation": ("str", ("fifo", "random")),
    "issuance_order": ("str", ("per-citizen", "mixed")),
    "dt_granularity": ("float", None),
    "tel_updates": ("str", ("upd", "bup")),
    "status_updates": ("str", ("none", "lockstep", "independent")),
    "batch_size": ("int", None),
    "batch_mix": ("str", ("citizen", "mixed", "ordered")),
    "publication_window": ("float", None),
    "holder_network": ("str", ("direct", "mixed")),
    "holder_status_reads": ("bool", None),
    "hosted_agents": ("str", ("none", "per-citizen", "shared")),
    "verifier_probing": ("bool", None),
    "identity_oracle": ("bool", None),
    "sealed_revocation_map": ("bool", None),
    "decoys": ("int", None),
    "log_join_material": ("bool", None),
    "holder_aids": ("str", ("nontransferable", "transferable", "delegated", "shared")),
    "holder_witnesses": ("str", ("pool", "per-citizen")),
    "copy_template": ("str", ("fresh", "cloned-attributes", "shared-edge")),
    "first_seen": ("str", ("exact", "constant")),
    "anchor_order": ("str", ("issuance", "per-citizen", "batched", "shuffled")),
    "retention": ("table", None),
}
_RETENTION = {kind: ("days", None) for kind in KINDS}
_PARTY = {"name": ("str", None), "kind": ("str", None), "compartments": ("strs", None),
          "obtains_at": ("float", None), "terms": ("strs", None), "context_bits": ("float", None)}
_CLAIM = {"party": ("str", None), "metric": ("str", METRICS), "op": ("str", OPS),
          "threshold": ("float", None)}
_TOP = {"run": ("table", None), "population": ("table", None), "citizens": ("table", None),
        "domain": ("tables", None), "verifier": ("tables", None),
        "presentation": ("tables", None), "stack": ("table", None), "party": ("tables", None),
        "claim": ("tables", None)}

# Far beyond any population, count or time a scenario needs (1e10 seconds is three centuries),
# and small enough that every accepted time converts to a timestamp.
MAX_NUMBER = 1e10
# The scored population is 3.5 million; fifty million rows keeps the table under a gigabyte.
MAX_POPULATION = 50_000_000
# How long a holder has to admit a copy once it is issued; no presentation precedes it.
ADMISSION = 60.0


def _number(v, infinite: bool) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, int):
        return abs(v) <= MAX_NUMBER
    if isnan(v):
        return False
    return abs(v) <= MAX_NUMBER or (infinite and v == float("inf"))


_CHECKS = {
    "int": lambda v: isinstance(v, int) and not isinstance(v, bool) and abs(v) <= MAX_NUMBER,
    "float": lambda v: _number(v, infinite=False),
    # Retention alone may be infinite: a store that never expires anything.
    "days": lambda v: _number(v, infinite=True),
    "str": lambda v: isinstance(v, str),
    "bool": lambda v: isinstance(v, bool),
    "strs": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
    "floats": lambda v: isinstance(v, list) and all(_number(x, infinite=False) for x in v),
    "table": lambda v: isinstance(v, dict),
    "tables": lambda v: isinstance(v, list) and all(isinstance(x, dict) for x in v),
}


def _take(table: dict, path: str, spec: dict) -> dict:
    for key in table:
        if key not in spec:
            raise errors.SCENARIO_UNKNOWN(param=f"{path}{key}", reason="the suite has no such "
                                          "parameter.")
    out = {}
    for key, (kind, allowed) in spec.items():
        if key not in table:
            raise errors.SCENARIO_MISSING(param=f"{path}{key}")
        value = table[key]
        if not _CHECKS[kind](value):
            raise errors.SCENARIO_UNKNOWN(param=f"{path}{key}", reason=f"expected {kind}.")
        if allowed is not None and value not in allowed:
            raise errors.SCENARIO_RANGE(param=f"{path}{key}", value=value,
                                        reason=f"it must be one of {', '.join(allowed)}.")
        out[key] = float(value) if kind in ("float", "days") else value
    return out


def _require(ok: bool, param: str, value, reason: str) -> None:
    if not ok:
        raise errors.SCENARIO_RANGE(param=param, value=value, reason=reason)


NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


def _named(name: str, param: str) -> str:
    """A party, verifier or domain name: it becomes part of compartment names and file names,
    so it is a lower-case slug."""
    _require(bool(NAME.fullmatch(name)), param, name,
             "names are lower-case letters, digits and hyphens, at most 64, starting with a "
             "letter or digit.")
    return name


def _unique(names, param):
    seen = set()
    for name in names:
        if name in seen:
            raise errors.SCENARIO_NAME(param=param, name=name)
        seen.add(name)


@dataclass(frozen=True)
class Run:
    seed: int
    adapter: str
    confidence_cut: float


@dataclass(frozen=True)
class Citizens:
    count: int
    copies: int
    issuance_period: float
    copy_interval: float


@dataclass(frozen=True)
class PresentationPlan:
    verifier: str
    domain: str
    disclose: tuple[str, ...]
    per_citizen: int
    start: float
    end: float


@dataclass(frozen=True)
class Stack:
    registry_scope: str
    registry_allocation: str
    issuance_order: str
    dt_granularity: float
    tel_updates: str
    status_updates: str
    batch_size: int
    batch_mix: str
    publication_window: float
    holder_network: str
    holder_status_reads: bool
    hosted_agents: str
    verifier_probing: bool
    identity_oracle: bool
    sealed_revocation_map: bool
    decoys: int
    log_join_material: bool
    holder_aids: str
    holder_witnesses: str
    copy_template: str
    first_seen: str
    anchor_order: str
    retention: dict[str, float]


@dataclass(frozen=True)
class Party:
    name: str
    kind: str
    compartments: tuple[str, ...]
    obtains_at: float
    terms: tuple[str, ...]
    context_bits: float


@dataclass(frozen=True)
class Claim:
    party: str
    metric: str
    op: str
    threshold: float


@dataclass(frozen=True)
class Scenario:
    digest: str
    run: Run
    population: PopulationSpec
    citizens: Citizens
    mandatory: dict[str, bool]
    verifiers: tuple[str, ...]
    presentations: tuple[PresentationPlan, ...]
    stack: Stack
    parties: tuple[Party, ...]
    claims: tuple[Claim, ...]

    def population_spec(self) -> PopulationSpec:
        return self.population

    def compartment_names(self) -> set[str]:
        """Every compartment this scenario's world has, which an adapter must account for."""
        names = {k for k in SINGLE_KINDS}
        names |= {f"verifier:{v}" for v in self.verifiers}
        names |= {f"issuing-home:{h}" for h in range(self.population.homes)}
        names |= {f"access-log:{r}" for r in ACCESS_LOG_ROLES}
        return names


def _population(table: dict) -> PopulationSpec:
    p = _take(table, "population.", _POPULATION)
    _require(1 <= p["size"] <= MAX_POPULATION, "population.size", p["size"],
             f"it must lie between 1 and {MAX_POPULATION:,}, the most rows the generated table "
             "holds in memory.")
    _require(p["homes"] >= 1, "population.homes", p["homes"], "it must be at least 1.")
    attrs = []
    for i, raw in enumerate(p["attribute"]):
        a = _take(raw, f"population.attribute[{i}].", _ATTRIBUTE)
        attrs.append(Attribute(a["name"], tuple(a["values"]),
                               tuple(float(x) for x in a["probabilities"]), a["sensitive"]))
    _unique([a.name for a in attrs], "population.attribute")
    corrs = []
    for i, raw in enumerate(p["correlation"]):
        c = _take(raw, f"population.correlation[{i}].", _CORRELATION)
        corrs.append(Correlation(c["a"], c["b"], c["rho"]))
    return PopulationSpec(size=p["size"], seed=p["seed"], attributes=tuple(attrs),
                          correlations=tuple(corrs), homes=p["homes"],
                          home_assignment=p["home_assignment"])


def _check_compartment(name: str, param: str, verifiers, homes: int) -> None:
    kind, instance = parse_compartment_name(name)
    if kind == "verifier" and instance not in verifiers:
        raise errors.SCENARIO_COMPARTMENT(param=param, name=name,
                                          reason="no verifier of that id is declared.")
    if kind == "issuing-home" and instance not in {str(h) for h in range(homes)}:
        raise errors.SCENARIO_COMPARTMENT(param=param, name=name,
                                          reason=f"homes are numbered 0 to {homes - 1}.")
    if kind == "access-log" and instance not in ACCESS_LOG_ROLES:
        raise errors.SCENARIO_COMPARTMENT(
            param=param, name=name, reason=f"access logs are kept by {', '.join(ACCESS_LOG_ROLES)}.")


def loads(text: str) -> Scenario:
    raw_bytes = text.encode()
    if len(raw_bytes) > MAX_BYTES:
        raise errors.SCENARIO_SIZE(size=len(raw_bytes), limit=MAX_BYTES)
    try:
        doc = tomllib.loads(text)
    # TOMLDecodeError, the ValueError an oversized integer raises, and the RecursionError deeply
    # nested tables raise.
    except (ValueError, RecursionError) as exc:
        raise errors.SCENARIO_FORMAT(reason=str(exc)) from None
    top = _take(doc, "", _TOP)

    run = Run(**_take(top["run"], "run.", _RUN))
    _require(0.0 <= run.confidence_cut <= 1.0, "run.confidence_cut", run.confidence_cut,
             "it must lie in [0, 1].")
    population = _population(top["population"])
    attr_names = {a.name for a in population.attributes}

    citizens = Citizens(**_take(top["citizens"], "citizens.", _CITIZENS))
    for key in ("count", "copies"):
        _require(getattr(citizens, key) >= 1, f"citizens.{key}", getattr(citizens, key),
                 "it must be at least 1.")
    _require(citizens.issuance_period > 0, "citizens.issuance_period", citizens.issuance_period,
             "it must be positive.")
    _require(citizens.copy_interval >= 0, "citizens.copy_interval", citizens.copy_interval,
             "it must not be negative.")
    last = citizens.issuance_period + citizens.copies * citizens.copy_interval + ADMISSION
    _require(last <= MAX_NUMBER, "citizens.copy_interval", citizens.copy_interval,
             f"issuance would run past {MAX_NUMBER:g} seconds.")

    domains = [_take(d, f"domain[{i}].", _DOMAIN) for i, d in enumerate(top["domain"])]
    _unique([_named(d["name"], "domain.name") for d in domains], "domain")
    mandatory = {d["name"]: d["mandatory"] for d in domains}
    verifiers = tuple(_take(v, f"verifier[{i}].", _VERIFIER)["id"]
                      for i, v in enumerate(top["verifier"]))
    _unique([_named(v, "verifier.id") for v in verifiers], "verifier")

    plans = []
    for i, raw in enumerate(top["presentation"]):
        path = f"presentation[{i}]."
        p = _take(raw, path, _PRESENTATION)
        _require(p["verifier"] in verifiers, path + "verifier", p["verifier"],
                 "no verifier of that id is declared.")
        _require(p["domain"] in mandatory, path + "domain", p["domain"],
                 "no domain of that name is declared.")
        for name in p["disclose"]:
            _require(name in attr_names, path + "disclose", name,
                     "the population has no such attribute.")
        _require(p["per_citizen"] >= 1, path + "per_citizen", p["per_citizen"],
                 "it must be at least 1.")
        _require(p["end"] > p["start"] >= 0, path + "end", p["end"],
                 "a window ends after it starts, and starts at or after 0.")
        last_copy = (citizens.issuance_period + citizens.copies * citizens.copy_interval
                     + ADMISSION)
        _require(p["start"] >= last_copy, path + "start", p["start"],
                 f"presentations start once issuance and admission are over, at {last_copy} "
                 "seconds, so no copy is presented before its holder has it.")
        plans.append(PresentationPlan(p["verifier"], p["domain"], tuple(p["disclose"]),
                                      p["per_citizen"], p["start"], p["end"]))
    used = sum(p.per_citizen for p in plans)
    _require(used <= citizens.copies, "presentation[].per_citizen", used,
             f"each presentation uses a fresh copy, and a citizen holds {citizens.copies}.")

    s = _take(top["stack"], "stack.", _STACK)
    s["retention"] = _take(s["retention"], "stack.retention.", _RETENTION)
    for key in ("dt_granularity", "publication_window", "batch_size", "decoys"):
        _require(s[key] >= 0, f"stack.{key}", s[key], "it must not be negative.")
    for key in ("dt_granularity", "publication_window"):
        _require(s[key] == 0 or s[key] >= 1e-6, f"stack.{key}", s[key],
                 "it is 0, for none, or at least a microsecond.")
    for kind, days in s["retention"].items():
        _require(days >= 0, f"stack.retention.{kind}", days, "it must not be negative.")
    stack = Stack(**s)

    parties = []
    for i, raw in enumerate(top["party"]):
        path = f"party[{i}]."
        p = _take(raw, path, _PARTY)
        _named(p["name"], path + "name")
        if p["kind"] not in PARTY_KINDS:
            raise errors.SCENARIO_PARTY_KIND(party=p["name"], kind=p["kind"],
                                             kinds=", ".join(PARTY_KINDS))
        for name in p["compartments"]:
            _check_compartment(name, path + "compartments", verifiers, population.homes)
        for name in p["terms"]:
            if name not in p["compartments"]:
                raise errors.SCENARIO_COMPARTMENT(param=path + "terms", name=name,
                                                  reason="terms name compartments the party "
                                                  "holds.")
        if p["kind"] == "government" and p["terms"]:
            raise errors.SCENARIO_GOVERNMENT_TERMS(party=p["name"])
        _require(p["obtains_at"] >= 0, path + "obtains_at", p["obtains_at"],
                 "it must not be negative.")
        _require(p["context_bits"] >= 0, path + "context_bits", p["context_bits"],
                 "it must not be negative.")
        parties.append(Party(p["name"], p["kind"], tuple(p["compartments"]), p["obtains_at"],
                             tuple(p["terms"]), p["context_bits"]))
    _unique([p.name for p in parties], "party")

    claims = []
    for i, raw in enumerate(top["claim"]):
        c = Claim(**_take(raw, f"claim[{i}].", _CLAIM))
        _require(c.party in {p.name for p in parties}, f"claim[{i}].party", c.party,
                 "no party of that name is declared.")
        claims.append(c)

    return Scenario(digest=hashlib.sha256(raw_bytes).hexdigest(), run=run, population=population,
                    citizens=citizens, mandatory=mandatory, verifiers=verifiers,
                    presentations=tuple(plans), stack=stack, parties=tuple(parties),
                    claims=tuple(claims))


def load(path: Path) -> Scenario:
    return loads(Path(path).read_text())
