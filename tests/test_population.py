"""The population model (docs/test-plan.md Part B item 4)."""

from math import log2
from statistics import NormalDist

import numpy as np
import pytest
from bakobo.errors import BakoboError

from keri_priv_analysis.population import Attribute, Correlation, PopulationSpec, generate

AGE = Attribute("age-band", ("18-29", "30-49", "50+"), (0.25, 0.4, 0.35), sensitive=False)
SMOKER = Attribute("smoker", ("no", "yes"), (0.8, 0.2), sensitive=True)
REGION = Attribute("region", ("north", "south", "east", "west"), (0.25, 0.25, 0.25, 0.25),
                   sensitive=False)


def _spec(**overrides):
    base = {"size": 200_000, "seed": 7, "attributes": (AGE, SMOKER, REGION),
                "correlations": (Correlation("age-band", "smoker", 0.5),),
                "homes": 4, "home_assignment": "uniform"}
    base.update(overrides)
    return PopulationSpec(**base)


def test_marginals_match_their_declarations():
    pop = generate(_spec())
    for attr in (AGE, SMOKER, REGION):
        counts = np.bincount(pop.codes[attr.name], minlength=len(attr.values)) / pop.size
        assert counts == pytest.approx(attr.probabilities, abs=0.005)


def test_declared_correlation_shapes_the_joint_distribution():
    # Expected joint cell (age 50+, smoker yes), computed independently of the module: sample the
    # same Gaussian copula with a different seed and threshold it.
    rng = np.random.default_rng(12345)
    z = rng.multivariate_normal([0, 0], [[1, 0.5], [0.5, 1]], size=400_000)
    age_cut = NormalDist().inv_cdf(0.65)  # above this the age band is 50+
    smoke_cut = NormalDist().inv_cdf(0.8)  # above this the smoker value is yes
    expected = np.mean((z[:, 0] > age_cut) & (z[:, 1] > smoke_cut))
    pop = generate(_spec())
    got = np.mean((pop.codes["age-band"] == 2) & (pop.codes["smoker"] == 1))
    assert got == pytest.approx(expected, abs=0.004)
    # And it is clearly not what independence would give (0.35 * 0.2 = 0.07).
    assert got > 0.085


def test_same_seed_same_table_byte_for_byte_and_a_new_seed_differs():
    a, b = generate(_spec(size=5000)), generate(_spec(size=5000))
    assert a.digest() == b.digest()
    assert all((a.codes[k] == b.codes[k]).all() for k in a.codes)
    assert generate(_spec(size=5000, seed=8)).digest() != a.digest()


def test_rows_match_counts_and_bits():
    pop = generate(_spec(size=1000))
    row = pop.row(17)
    assert set(row) == {"age-band", "smoker", "region", "issuing-home"}
    m = pop.match_count(row)
    assert m >= 1
    expected = sum(all(pop.row(i)[k] == v for k, v in row.items()) for i in range(1000))
    assert m == expected
    assert pop.bits(row) == pytest.approx(log2(1000 / m))
    assert pop.bits({}) == 0.0
    assert pop.max_bits == pytest.approx(log2(1000))


def test_uniform_homes_carry_about_log2_n_bits_and_sharded_homes_follow_an_attribute():
    pop = generate(_spec(size=100_000, homes=8))
    assert pop.bits({"issuing-home": "3"}) == pytest.approx(3.0, abs=0.05)
    sharded = generate(_spec(size=20_000, home_assignment="region"))
    for i in range(50):
        row = sharded.row(i)
        assert row["issuing-home"] == str(REGION.values.index(row["region"]) % 4)


def test_sensitive_attributes_are_listed():
    assert generate(_spec(size=100)).sensitive == ("smoker",)


@pytest.mark.parametrize("overrides,code", [
    ({"attributes": (Attribute("x", ("a", "b"), (0.5, 0.6), False),), "correlations": ()},
     "e.input.range.population-marginal.f"),
    ({"attributes": (Attribute("x", ("a",), (0.5, 0.5), False),), "correlations": ()},
     "e.input.range.population-marginal.f"),
    ({"correlations": (Correlation("age-band", "height", 0.2),)},
     "e.input.range.population-attribute.f"),
    ({"correlations": (Correlation("age-band", "smoker", 1.5),)},
     "e.input.range.population-correlation.f"),
    ({"correlations": (Correlation("age-band", "smoker", 0.9), Correlation("smoker", "region", 0.9),
                        Correlation("age-band", "region", -0.9))},
     "e.input.range.population-correlation.f"),
    ({"home_assignment": "shoe-size"}, "e.input.range.population-attribute.f"),
    ({"homes": 0}, "e.input.range.population-homes.f"),
    ({"size": 0}, "e.input.range.population-size.f"),
    ({"attributes": (AGE, AGE)}, "e.input.multi.population-attribute.f"),
])
def test_bad_specs_are_refused_with_codes(overrides, code):
    with pytest.raises(BakoboError) as raised:
        generate(_spec(**overrides))
    assert raised.value.code == code


def test_a_value_the_table_lacks_is_refused():
    pop = generate(_spec(size=100))
    with pytest.raises(BakoboError) as raised:
        pop.match_count({"age-band": "12"})
    assert raised.value.code == "e.input.range.population-value.f"
    with pytest.raises(BakoboError):
        pop.match_count({"eye-colour": "blue"})
