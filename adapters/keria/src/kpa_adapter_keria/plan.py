"""Turn a scenario into the plan the KERIA driver performs, and keep what the scorer needs.

The draw follows the generator's: the same seed picks the same population rows for the citizens,
each citizen's home is its row's home, and issuance and presentation times are drawn from the
scenario's windows. The driver then performs every issuance and every presentation in the order
of those times, one after another, because a real stack cannot wait out the scenario's month.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from keri_priv_analysis.population import HOME, Population
from keri_priv_analysis.scenario import Scenario


@dataclass(frozen=True)
class Issuance:
    citizen: int
    copy: int
    time: float


@dataclass(frozen=True)
class Showing:
    handle: str
    citizen: int
    copy: int
    verifier: str
    domain: str
    time: float
    disclose: tuple[str, ...]


@dataclass
class Plan:
    rows: list[int]
    homes: list[int]
    attributes: list[str]  # the attributes the credential carries
    issuance: list[Issuance]  # in the order performed
    showings: list[Showing]  # in the order performed
    driver: dict  # what the driver reads


def credential_attributes(scenario: Scenario) -> list[str]:
    """The credential carries every attribute any presentation discloses. An IPEX grant presents
    the whole credential, so the adapter refuses any presentation that discloses fewer
    (settings.check_disclosure)."""
    out = []
    for plan in scenario.presentations:
        out += [name for name in plan.disclose if name not in out]
    return out


def build(scenario: Scenario, population: Population) -> Plan:
    rng = np.random.default_rng([scenario.run.seed, 2])
    c = scenario.citizens
    rows = [int(r) for r in rng.choice(population.size, size=c.count, replace=False)]
    homes = [int(population.codes[HOME][r]) for r in rows]
    if scenario.stack.issuance_order == "per-citizen":
        starts = np.sort(rng.uniform(0, c.issuance_period, size=c.count))
        issuance = [Issuance(n, j, float(start) + j * c.copy_interval)
                    for n, start in enumerate(starts) for j in range(c.copies)]
    else:
        issuance = [Issuance(n, j, float(t)) for n in range(c.count)
                    for j, t in enumerate(rng.uniform(0, c.issuance_period, size=c.copies))]
    issuance.sort(key=lambda i: (i.time, i.citizen, i.copy))
    showings = []
    for n in range(c.count):
        wallet = [int(j) for j in rng.permutation(c.copies)]
        for p in scenario.presentations:
            for _ in range(p.per_citizen):
                showings.append(Showing(rng.bytes(8).hex(), n, wallet.pop(), p.verifier,
                                        p.domain, float(rng.uniform(p.start, p.end)),
                                        p.disclose))
    showings.sort(key=lambda s: (s.time, s.handle))
    attributes = credential_attributes(scenario)
    driver = {
        "seed": scenario.run.seed,
        "homes": scenario.population.homes,
        "verifiers": list(scenario.verifiers),
        "attributes": attributes,
        "copies": c.copies,
        "dt_granularity": scenario.stack.dt_granularity,
        "citizens": [{"home": homes[n], "attributes": {
            a: population.row(rows[n])[a] for a in attributes}} for n in range(c.count)],
        "issuance": [{"citizen": i.citizen, "copy": i.copy} for i in issuance],
        "presentations": [{"citizen": s.citizen, "copy": s.copy, "verifier": s.verifier}
                          for s in showings],
    }
    return Plan(rows=rows, homes=homes, attributes=attributes, issuance=issuance,
                showings=showings, driver=driver)
