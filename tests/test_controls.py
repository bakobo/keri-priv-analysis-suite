"""Every attack against its positive and negative control (docs/test-plan.md Part B item 1).

The positive control is built so the attack's vector leaks: the attack must link it with precision
1.0 and at least the recall it declares. The negative control is built so the vector does not
leak: the attack's precision must be indistinguishable from the base rate by a one-sided binomial
test at alpha = 0.01, on a control big enough to give that test power 0.95 against precision 2b.
"""

from collections import Counter
from math import log2

import numpy as np
import pytest
from worlds import world

from keri_priv_analysis import stats
from keri_priv_analysis.attacks import CATALOGUE, dedupe
from keri_priv_analysis.population import HOME
from keri_priv_analysis.scoring import PartyTerms, score

POSITIVE = {"count": 20, "copies": 4}
# One home: with several, any grouping inside a home's KEL or registry also carries the home
# bucket, which is the issuer-AID attack's vector and is controlled there.
NEGATIVE = {"count": 40, "copies": 4, "homes": 1}
EVERYTHING = PartyTerms(kind="hacker", terms=frozenset(), context_bits=0.0)
JOINING = [a for a in CATALOGUE if a.kind != "bits"]


@pytest.mark.parametrize("attack", JOINING, ids=lambda a: a.name)
def test_positive_control_is_linked(attack):
    s, population, cs, truth, k = world(**POSITIVE, **attack.positive)
    joins = dedupe(attack.run(cs, k))
    result = score(EVERYTHING, cs, joins, [], truth, population, cut=1.0, mandatory=s.mandatory)
    assert result.joins > 0
    assert result.precision == 1.0
    assert result.recall >= attack.recall


def _base_rate(attack, cs, truth, joins):
    if attack.kind == "identity":
        identities = sum(len(rows) for c in cs.of_kind("identity-proofing")
                         for rows in c.records.values())
        return stats.identity_base_rate(identities), [j for j in joins
                                                       if "id:" in (j.a[:3], j.b[:3])]
    per_citizen = Counter(truth.presentations[p.handle] for p in cs.presentations())
    return stats.pairwise_base_rate(list(per_citizen.values())), joins


@pytest.mark.parametrize("attack", JOINING, ids=lambda a: a.name)
def test_negative_control_scores_at_chance(attack):
    _s, _population, cs, truth, k = world(**NEGATIVE, **attack.negative)
    joins = dedupe(attack.run(cs, k))
    b, considered = _base_rate(attack, cs, truth, joins)
    if attack.kind == "identity":
        candidates = len(cs.presentations()) * round(1 / b)
    else:
        candidates = len(cs.presentations()) * (len(cs.presentations()) - 1) // 2
    needed = stats.required_joins(b)
    assert needed is not None and candidates >= needed, "the negative control is too small"
    correct = sum(1 for j in considered
                  if truth.citizen_of(j.a) is not None
                  and truth.citizen_of(j.a) == truth.citizen_of(j.b))
    assert stats.at_chance(correct, len(considered), b), (correct, len(considered), b)


def _bucket(attack, **settings):
    _s, population, cs, truth, k = world(count=40, copies=4, size=400_000, **settings)
    observations = attack.run(cs, k)
    assert len(observations) == len(cs.presentations())
    return population, truth, observations


def test_issuer_bucket_negative_control_adds_log2_n_bits():
    attack = next(a for a in CATALOGUE if a.name == "issuer-aid-bucket")
    population, _truth, observations = _bucket(attack, **attack.negative)
    homes = population.spec.homes
    for o in observations:
        bits = log2(population.size / np.sum(population.codes[HOME] == int(o.value)))
        assert bits == pytest.approx(log2(homes), abs=0.05)


def test_issuer_bucket_positive_control_adds_the_sharding_attributes_bits():
    attack = next(a for a in CATALOGUE if a.name == "issuer-aid-bucket")
    population, truth, observations = _bucket(attack, **attack.positive)
    county = population.codes["county"]
    for o in observations:
        citizen = truth.citizen_of(o.node)
        row = truth.citizen_rows[citizen]
        assert o.value == population.row(row)[HOME]
        # The home is the county's index modulo the homes, so it reveals the county group.
        group = np.isin(county, [c for c in range(5) if c % population.spec.homes == int(o.value)])
        assert population.bits({HOME: o.value}) == pytest.approx(
            log2(population.size / group.sum()))


# Every vector the generator can leak, switched off at once. On this world every attack must score
# at chance: an attack that links anything here is reading a signal that is not its vector.
QUIET = {"issuance_order": "mixed", "registry_allocation": "random", "dt_granularity": 86400.0,
         "anchor_order": "shuffled", "first_seen": "constant", "holder_network": "mixed",
         "hosted_agents": "shared", "verifier_probing": True, "publication_window": 86400.0,
         "batch_size": 8, "batch_mix": "mixed", "status_updates": "independent",
         "sealed_revocation_map": True, "identity_oracle": True, "holder_aids": "transferable",
         "holder_witnesses": "pool", "copy_template": "fresh"}


@pytest.mark.parametrize("attack", JOINING, ids=lambda a: a.name)
def test_every_attack_scores_at_chance_on_the_quiet_world(attack):
    _s, _population, cs, truth, k = world(**NEGATIVE, **QUIET)
    assert attack.missing(cs) == []
    joins = dedupe(attack.run(cs, k))
    b, considered = _base_rate(attack, cs, truth, joins)
    correct = sum(1 for j in considered
                  if truth.citizen_of(j.a) is not None
                  and truth.citizen_of(j.a) == truth.citizen_of(j.b))
    assert stats.at_chance(correct, len(considered), b), (correct, len(considered), b)
