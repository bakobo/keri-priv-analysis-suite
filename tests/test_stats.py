"""The negative-control statistics of docs/test-plan.md Part B item 1."""

from fractions import Fraction
from math import comb

import pytest

from keri_priv_analysis import stats


def _sf_exact(k, n, p):
    p = Fraction(p)
    return float(sum(comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k, n + 1)))


def test_pairwise_base_rate_is_the_random_guessers_precision():
    # Three citizens with 3, 2 and 1 presentations: 3 + 1 + 0 same-citizen pairs out of C(6,2)=15.
    assert stats.pairwise_base_rate([3, 2, 1]) == pytest.approx(4 / 15)
    assert stats.pairwise_base_rate([1, 1, 0]) == 0.0
    assert stats.pairwise_base_rate([1]) == 0.0


def test_identity_base_rate():
    assert stats.identity_base_rate(250) == pytest.approx(1 / 250)
    assert stats.identity_base_rate(0) == 0.0


@pytest.mark.parametrize("k,n,p", [(8, 10, 0.5), (0, 7, 0.3), (3, 3, 0.2), (1, 50, 0.01),
                                   (11, 10, 0.5), (5, 40, 0.0), (0, 40, 1.0), (40, 40, 1.0)])
def test_binomial_survival_function_matches_exact_sum(k, n, p):
    assert stats.binom_sf(k, n, p) == pytest.approx(_sf_exact(k, n, p), abs=1e-12)


def test_critical_count_is_the_smallest_rejecting_count():
    n, p0, alpha = 200, 0.05, 0.01
    c = stats.critical_count(n, p0, alpha)
    assert _sf_exact(c, n, p0) <= alpha < _sf_exact(c - 1, n, p0)


def test_required_sample_has_the_stated_power_and_a_smaller_one_does_not():
    p0 = 0.1
    n = stats.required_joins(p0, alpha=0.01, power=0.95)
    c = stats.critical_count(n, p0, 0.01)
    assert _sf_exact(c, n, 2 * p0) >= 0.95
    shorter = int(n * 0.8)
    c_short = stats.critical_count(shorter, p0, 0.01)
    assert _sf_exact(c_short, shorter, 2 * p0) < 0.95


def test_required_sample_is_infinite_when_base_rate_leaves_no_room():
    # Precision 2b cannot exceed 1, and a base rate of 0 cannot be doubled into anything testable.
    assert stats.required_joins(0.6) is None
    assert stats.required_joins(0.0) is None


def test_negative_control_verdict():
    # 3 correct of 100 at b = 0.02 is consistent with chance; 12 of 100 is not.
    assert stats.at_chance(3, 100, 0.02)
    assert not stats.at_chance(12, 100, 0.02)
    # No joins at all passes: the positive control already showed the attack can find one.
    assert stats.at_chance(0, 0, 0.02)
