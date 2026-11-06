"""The adapter contract suite (docs/test-plan.md Part B item 5).

Every adapter, the generator included, must pass these checks on any scenario it accepts. Each
check returns a list of problems in plain sentences; an empty list is a pass.
"""

from __future__ import annotations

from collections import Counter
from numbers import Integral

from . import cesr
from .model import CompartmentSet, GroundTruth, Knowledge, identifiers
from .population import Population
from .scenario import Scenario


def compartments_accounted(scenario: Scenario, cs: CompartmentSet) -> list[str]:
    want, have = scenario.compartment_names(), set(cs.names())
    return ([f"compartment {n} is missing: report it absent or not measured, never omit it"
             for n in sorted(want - have)]
            + [f"compartment {n} is not one this scenario has" for n in sorted(have - want)])


def presentation_counts(scenario: Scenario, cs: CompartmentSet, truth: GroundTruth,
                        population: Population) -> list[str]:
    """Each citizen made exactly the scenario's presentations: per verifier and domain, inside the
    plan's window, disclosing exactly the plan's attributes with the citizen's own values."""
    problems = []
    handles = [p.handle for p in cs.presentations()]
    for handle, n in Counter(handles).items():
        if n > 1:
            problems.append(f"presentation handle {handle} appears {n} times")
    if set(handles) != set(truth.presentations):
        problems.append("the presentations exported and those in ground truth differ")
    # Each plan is kept apart: a presentation belongs to the first plan with its verifier,
    # domain and disclosed attributes whose window holds its time, and each plan's count is met
    # on its own, so two windows for the same disclosures are not pooled. Overlapping windows
    # want a matching rather than first fit (~4d6u).
    plans = scenario.presentations
    citizens = len(truth.citizen_rows)
    if citizens != scenario.citizens.count:
        problems.append(f"ground truth has {citizens} citizens, but the scenario specifies "
                        f"{scenario.citizens.count}")
    unrowed = set()
    for citizen, r in enumerate(truth.citizen_rows):
        if isinstance(r, bool) or not (isinstance(r, Integral) and 0 <= r < population.size):
            unrowed.add(citizen)
            problems.append(f"citizen {citizen} is given population row {r!r}, which is not a row "
                            "of the population table")
    got = Counter()
    for p in cs.presentations():
        key = (p.verifier, p.domain, frozenset(p.disclosed))
        same = [i for i, plan in enumerate(plans)
                if (plan.verifier, plan.domain, frozenset(plan.disclose)) == key]
        fits = [i for i in same if plans[i].start <= p.time <= plans[i].end]
        if not same:
            problems.append(f"presentation {p.handle} goes to {p.verifier} in {p.domain} "
                            f"disclosing {sorted(p.disclosed)}, which no plan names")
        elif not fits:
            problems.append(f"presentation {p.handle} at {p.time} falls in no window of a plan "
                            f"for {p.verifier} in {p.domain} disclosing {sorted(p.disclosed)}")
        if p.handle not in truth.presentations:
            continue
        citizen = truth.presentations[p.handle]
        if isinstance(citizen, bool) or not (isinstance(citizen, int) and 0 <= citizen < citizens):
            problems.append(f"presentation {p.handle} belongs to citizen {citizen!r}, which is "
                            "not a simulated citizen")
            continue
        if fits:
            got[(citizen, fits[0])] += 1
        if citizen in unrowed:
            continue
        row = population.row(truth.citizen_rows[citizen])
        # The values are the adapter's account of them, not yet read from the bytes (~3sw5).
        if any(row.get(a) != v for a, v in p.disclosed.items()):
            problems.append(f"presentation {p.handle} discloses {sorted(p.disclosed)} with "
                            "values its citizen does not hold")
    for citizen in range(citizens):
        for i, plan in enumerate(plans):
            if (have := got[(citizen, i)]) != plan.per_citizen:
                problems.append(f"citizen {citizen} made {have} presentations to {plan.verifier} "
                                f"in {plan.domain} disclosing {sorted(plan.disclose)} between "
                                f"{plan.start} and {plan.end}, but the scenario specifies "
                                f"{plan.per_citizen}")
    return problems


def _issued(cs: CompartmentSet, truth: GroundTruth, knowledge: Knowledge) -> set[str]:
    known = (set(truth.artifacts) | set(truth.decoys) | set(knowledge.issuers)
             | set(knowledge.infrastructure))
    for compartment in cs.of_kind("public"):
        for name, data in compartment.streams.items():
            if name.startswith(("kel:", "tel:")):
                for message in cesr.messages(data, name):
                    known |= set(identifiers(repr(message)))
    return known


def identifiers_issued(cs: CompartmentSet, truth: GroundTruth, knowledge: Knowledge) -> list[str]:
    """Every identifier in a record, a log line or a presentation is one the adapter issued."""
    known = _issued(cs, truth, knowledge)
    problems = []
    for compartment in cs.present():
        texts = [line.text for line in compartment.logs]
        texts += [repr(row) for rows in compartment.records.values() for row in rows]
        texts += [f"{p.said} {p.registry} {p.issuer} {p.holder}"
                  for p in compartment.presentations]
        unknown = sorted({i for text in texts for i in identifiers(text)} - known)
        if unknown:
            problems.append(f"compartment {compartment.name} names {len(unknown)} identifiers the "
                            f"adapter did not issue, such as {unknown[0]}")
    return problems


def _kel_problems(name: str, data: bytes) -> tuple[list[str], list[dict]]:
    pre = name.removeprefix("kel:")
    events = cesr.messages(data, name)
    strays = [e.get("t") for e in events if e.get("t") not in cesr.KEL_ILKS]
    if strays:
        return [f"{name} holds messages that are not key events: {', '.join(map(str, strays))}"], []
    accepted = cesr.verify_kel(data)
    # A stream may carry other AIDs' events first, such as a delegator's KEL before a delegated
    # inception; each AID in it must be accepted through its last event.
    for aid in dict.fromkeys(e["i"] for e in events):
        last = max(int(e["s"], 16) for e in events if e["i"] == aid)
        if accepted.get(aid) != last:
            return [(f"{name} does not verify: keripy accepted {aid} through "
                    f"{accepted.get(aid)} of {last}")], events
    if pre not in {e["i"] for e in events}:
        return [f"{name} holds no event of {pre}"], events
    return [], events


def streams_verify(cs: CompartmentSet) -> list[str]:
    """The public record has KELs and TELs, every KEL replays in keripy (the issuers' and the
    holder KELs verifiers resolved), every TEL chains and is sealed in a KEL, and every
    presentation's bytes carry the credential it names."""
    problems, kels = [], {}
    public = [n for c in cs.of_kind("public") for n in c.streams]
    if cs.presentations():
        for prefix, what in (("kel:", "an issuer KEL"), ("tel:", "a TEL")):
            if not any(n.startswith(prefix) for n in public):
                problems.append(f"the public record has no {what}, so nothing the "
                                "presentations rest on can be checked")
    for compartment in cs.of_kind("public"):
        for name, data in compartment.streams.items():
            if name.startswith("kel:"):
                found, events = _kel_problems(name, data)
                problems += found
                kels[name.removeprefix("kel:")] = cesr.seals(events)
        for name, data in compartment.streams.items():
            if name.startswith("tel:"):
                # Sealed in its own issuer's KEL, not merely in some issuer's.
                tel = cesr.messages(data, name)
                issuers = {cesr.tel_event(e)["issuer"] for e in tel} - {None}
                issuer = issuers.pop() if len(issuers) == 1 else None
                if issuer is None:
                    problems.append(f"{name} does not name exactly one issuer")
                for problem in cesr.verify_tel(tel, kels.get(issuer, {})):
                    problems.append(f"{name}: {problem}")
    for compartment in cs.of_kind("verifier"):
        for name, data in compartment.streams.items():
            if name.startswith("kel:"):
                problems += [f"{compartment.name} {p}" for p in _kel_problems(name, data)[0]]
    for p in cs.presentations():
        saids = {m.get("d") for m in cesr.messages(p.raw, f"presentation {p.handle}")}
        if p.said not in saids:
            problems.append(f"presentation {p.handle} does not carry credential {p.said}")
    return problems


def check(scenario: Scenario, cs: CompartmentSet, truth: GroundTruth, knowledge: Knowledge,
          population: Population) -> list[str]:
    return (compartments_accounted(scenario, cs)
            + presentation_counts(scenario, cs, truth, population)
            + identifiers_issued(cs, truth, knowledge) + streams_verify(cs))
