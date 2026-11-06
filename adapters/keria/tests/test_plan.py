import dataclasses

import numpy as np
from keri_priv_analysis.population import HOME

from kpa_adapter_keria import plan as planning


def test_the_credential_carries_every_disclosed_attribute_once(scenario):
    assert planning.credential_attributes(scenario) == ["age-band", "county"]


def test_citizens_are_the_generators_draw(scenario, population):
    p = planning.build(scenario, population)
    rng = np.random.default_rng([scenario.run.seed, 2])
    want = [int(r) for r in rng.choice(population.size, size=scenario.citizens.count,
                                       replace=False)]
    assert p.rows == want
    assert p.homes == [int(population.codes[HOME][r]) for r in want]
    for n, citizen in enumerate(p.driver["citizens"]):
        row = population.row(want[n])
        assert citizen == {"home": p.homes[n], "attributes": {"age-band": row["age-band"],
                                                              "county": row["county"]}}


def test_per_citizen_issuance_runs_each_citizens_copies_together(scenario, population):
    p = planning.build(scenario, population)
    times = [i.time for i in p.issuance]
    assert times == sorted(times) and len(p.issuance) == 4
    assert [i.citizen for i in p.issuance] == [p.issuance[0].citizen] * 2 + \
        [p.issuance[2].citizen] * 2
    first = p.issuance[0]
    assert abs(p.issuance[1].time - first.time - scenario.citizens.copy_interval) < 1e-9
    assert p.driver["issuance"] == [{"citizen": i.citizen, "copy": i.copy} for i in p.issuance]


def test_mixed_issuance_draws_each_copy_its_own_time(scenario, population):
    mixed = dataclasses.replace(scenario, stack=dataclasses.replace(scenario.stack,
                                                                    issuance_order="mixed"))
    p = planning.build(mixed, population)
    times = [i.time for i in p.issuance]
    assert times == sorted(times)
    assert all(0 <= t <= scenario.citizens.issuance_period for t in times)
    assert sorted((i.citizen, i.copy) for i in p.issuance) == [(0, 0), (0, 1), (1, 0), (1, 1)]


def test_each_presentation_shows_a_fresh_copy_in_its_window(scenario, population):
    p = planning.build(scenario, population)
    assert len(p.showings) == 4
    assert len({(s.citizen, s.copy) for s in p.showings}) == 4
    assert [s.time for s in p.showings] == sorted(s.time for s in p.showings)
    windows = {w.verifier: (w.start, w.end, w.domain) for w in scenario.presentations}
    for s in p.showings:
        start, end, domain = windows[s.verifier]
        assert start <= s.time <= end and s.domain == domain and len(s.handle) == 16
        assert s.disclose == ("age-band", "county")
    assert p.driver["presentations"] == [{"citizen": s.citizen, "copy": s.copy,
                                          "verifier": s.verifier} for s in p.showings]
    assert p.driver["seed"] == scenario.run.seed and p.driver["copies"] == 2
    assert planning.build(scenario, population).driver == p.driver
