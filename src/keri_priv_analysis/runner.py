"""Run a scenario: drive the adapter, check its contract, give each party what it obtained, run
every attack it can, score, and judge the claims. Everything lands in one run directory, from
which the report is generated (docs/test-plan.md, 'Outputs')."""

from __future__ import annotations

import dataclasses
import json
import platform
import statistics
from importlib import metadata
from pathlib import Path

from . import contract, errors, rundir
from .attacks import CATALOGUE, dedupe
from .catalogue import owners
from .model import Compartment, CompartmentSet, Join, Observation
from .population import generate
from .scenario import Scenario, loads
from .scoring import PartyScore, PartyTerms, score

DAY = 86400.0
ENTRY_POINTS = "keri_priv_analysis.adapters"


def adapter_for(name: str):
    """The adapter a scenario names: the generator, or one installed by an adapter project."""
    if name == "generator":
        from .generator import Generator
        return Generator()
    found = {e.name: e for e in metadata.entry_points(group=ENTRY_POINTS)}
    if name not in found:
        raise errors.ADAPTER_UNAVAILABLE(adapter=name,
                                         installed=", ".join(["generator", *sorted(found)]))
    return found[name].load()()


def _within(t: float, obtained: float, keep: float) -> bool:
    return obtained - keep * DAY <= t <= obtained


def obtained(compartment: Compartment, at: float, retention_days: float) -> Compartment:
    """What a party obtaining this compartment at time `at` gets: what existed by then, less what
    the compartment's retention had already expired (this.i 4ww9snv2). The public record's
    streams are kept whole."""
    if compartment.status != "present":
        return compartment
    keep = retention_days
    return dataclasses.replace(
        compartment,
        logs=[line for line in compartment.logs if _within(line.time, at, keep)],
        presentations=[p for p in compartment.presentations if _within(p.time, at, keep)],
        records={table: [row for row in rows
                         if "time" not in row or _within(float(row["time"]), at, keep)]
                 for table, rows in compartment.records.items()},
    )


def _metric(s: PartyScore, metric: str):
    values = {
        "reidentified": s.reidentified,
        "max_bits": max(s.bits, default=0.0),
        "median_bits": statistics.median(s.bits) if s.bits else 0.0,
        "precision": s.precision,
        "certain_share": s.certain_share,
        "flagged_domains": len(s.flagged),
        "max_increment": max(s.increment, default=0.0),
        "identity_exposed": s.identity_exposed,
        "breach_reidentified": s.breach_reidentified,
    }
    return values[metric]


def _holds(value: float, op: str, threshold: float) -> bool:
    return {"<=": value <= threshold, ">=": value >= threshold, "<": value < threshold,
            ">": value > threshold, "==": value == threshold}[op]


def _verdict(s: PartyScore, claim, measured: bool = True) -> tuple[str, float | None]:
    """A claim's verdict. It is not measured when no attack could run for the party, or when a
    compartment the party requires is absent or could not be exported: a zero then means nobody
    looked, or nobody could. The value measured so far is kept beside it."""
    value = _metric(s, claim.metric)
    if value is None or not measured:
        return "not-measured", value
    return ("pass" if _holds(value, claim.op, claim.threshold) else "fail"), value


def provenance(scenario: Scenario, adapter, population) -> dict:
    keri = metadata.distribution("keri")
    direct = json.loads(keri.read_text("direct_url.json") or "{}")
    return {
        "suite": metadata.version("keri-priv-analysis-suite"),
        "python": platform.python_version(),
        "keripy": {"version": keri.version,
                   "commit": direct.get("vcs_info", {}).get("commit_id", "")},
        "scenario_sha256": scenario.digest,
        "population": {"seed": scenario.population.seed, "size": scenario.population.size,
                       "sha256": population.digest()},
        "adapter": {"name": adapter.name, **adapter.provenance()},
    }


def _write_joins(out: Path, party: str, attack: str, joins, observations) -> None:
    """Every join and observation an attack made for a party, so each number can be recomputed."""
    where = out / "joins" / party
    where.mkdir(parents=True, exist_ok=True)
    (where / f"{attack}.json").write_text(json.dumps({
        "joins": sorted([j.a, j.b, j.confidence] for j in joins),
        "observations": sorted([o.node, o.attribute, o.value] for o in observations),
    }, indent=0) + "\n")


def run(scenario_text: str, out: Path) -> Path:
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise errors.RUN_EXISTS(path=str(out))
    scenario = loads(scenario_text)
    adapter = adapter_for(scenario.run.adapter)
    population = generate(scenario.population)
    cs, truth, knowledge = adapter.run(scenario, population)
    problems = contract.check(scenario, cs, truth, knowledge, population)
    if problems:
        raise errors.ADAPTER_CONTRACT(adapter=adapter.name, count=len(problems),
                                      first=problems[0])
    out.mkdir(parents=True, exist_ok=True)
    (out / "scenario.toml").write_text(scenario_text)
    rundir.write_compartments(out, cs)
    rundir.write_ground_truth(out, truth)
    rundir.write_knowledge(out, knowledge)
    results = {
        "provenance": provenance(scenario, adapter, population),
        "causes": adapter.causes(scenario),
        "owners": {**owners(), **getattr(adapter, "owners", dict)()},
        "parties": {},
        "claims": [],
    }
    loaded = rundir.read_compartments(out)  # attacks read what is on disk, nothing else
    combined: dict[str, PartyScore] = {}
    per_attack: dict[str, dict[str, PartyScore]] = {}
    for party in scenario.parties:
        view = CompartmentSet(
            obtained(loaded[name], party.obtains_at, scenario.stack.retention[loaded[name].kind])
            for name in party.compartments)
        terms = PartyTerms(kind=party.kind, terms=frozenset(party.terms),
                           context_bits=party.context_bits)
        joins: list[Join] = []
        observations: list[Observation] = []
        attacks, per_attack[party.name] = {}, {}
        for attack in CATALOGUE:
            missing = attack.missing(view)
            if missing:
                attacks[attack.name] = {"measured": False, "missing": missing}
                continue
            found = attack.run(view, knowledge)
            own_joins = dedupe(found) if attack.kind != "bits" else []
            own_obs = found if attack.kind == "bits" else []
            joins += own_joins
            observations += own_obs
            s = score(terms, view, own_joins, own_obs, truth, population,
                      scenario.run.confidence_cut, scenario.mandatory)
            per_attack[party.name][attack.name] = s
            attacks[attack.name] = {"measured": True, "joins": len(own_joins),
                                    "observations": len(own_obs), "score": s.to_json()}
            _write_joins(out, party.name, attack.name, own_joins, own_obs)
        joins = dedupe(joins)
        s = score(terms, view, joins, observations, truth, population,
                  scenario.run.confidence_cut, scenario.mandatory)
        combined[party.name] = s
        results["parties"][party.name] = {
            "kind": party.kind,
            "compartments": {c.name: c.status for c in view},
            "notes": {c.name: c.note for c in view if c.note},
            "attacks": attacks,
            "score": s.to_json(),
        }
    for claim in scenario.claims:
        held = results["parties"][claim.party]["compartments"].values()
        measured = bool(per_attack[claim.party]) and all(status == "present" for status in held)
        verdict, value = _verdict(combined[claim.party], claim, measured)
        alone = sorted(name for name, s in per_attack[claim.party].items()
                       if _verdict(s, claim)[0] == "fail")
        results["claims"].append({**dataclasses.asdict(claim), "verdict": verdict,
                                  "measured": value, "attacks": alone})
    (out / "results.json").write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
    from . import report
    report.write(out)
    return out
