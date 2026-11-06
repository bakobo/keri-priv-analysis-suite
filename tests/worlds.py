"""Small scenarios and cached generator worlds for the tests.

Each world is built once per test session, keyed by its parameters, because building one runs
keripy for every registry and issuance.
"""

import dataclasses
from functools import cache
from pathlib import Path

from keri_priv_analysis.generator import Generator
from keri_priv_analysis.population import generate
from keri_priv_analysis.scenario import load

SMOKE = Path(__file__).parent.parent / "scenarios" / "smoke.toml"


def scenario(count=20, copies=6, size=100_000, homes=4, home_assignment="uniform", seed=7,
             per_citizen=None, **stack):
    """The smoke scenario, shrunk. Each of its two presentation plans uses per_citizen copies,
    by default as many as half the copies allow, up to two."""
    s = load(SMOKE)
    per = per_citizen or max(1, min(2, copies // 2))
    assert 2 * per <= copies
    return dataclasses.replace(
        s,
        presentations=tuple(dataclasses.replace(p, per_citizen=per) for p in s.presentations),
        run=dataclasses.replace(s.run, seed=seed),
        citizens=dataclasses.replace(s.citizens, count=count, copies=copies),
        population=dataclasses.replace(s.population, size=size, homes=homes,
                                       home_assignment=home_assignment),
        stack=dataclasses.replace(s.stack, **stack),
    )


@cache
def _population(spec):
    return generate(spec)


@cache
def _world(key):
    s = scenario(**dict(key))
    population = _population(s.population)
    compartments, truth, knowledge = Generator().run(s, population)
    return s, population, compartments, truth, knowledge


def world(**params):
    """(scenario, population, compartments, ground truth, knowledge) for these parameters."""
    return _world(tuple(sorted(params.items())))
