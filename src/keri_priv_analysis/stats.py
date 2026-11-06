"""Base rates and the one-sided binomial test that a negative control must pass.

docs/test-plan.md Part B item 1: on its negative control an attack's precision must be
indistinguishable from the base rate b, the precision of a guesser who joins at random, by a
one-sided binomial test at alpha = 0.01. The control must be big enough that the test has power
0.95 to detect precision 2b.
"""

from __future__ import annotations

from math import comb, exp, lgamma, log

ALPHA = 0.01
POWER = 0.95


def pairwise_base_rate(per_citizen: list[int]) -> float:
    """b = sum_c C(k_c, 2) / C(K, 2), for an attack joining presentations to each other."""
    total = comb(sum(per_citizen), 2)
    if total == 0:
        return 0.0
    return sum(comb(k, 2) for k in per_citizen) / total


def identity_base_rate(candidates: int) -> float:
    """b = 1 / I, for an attack joining presentations to I candidate legal identities."""
    return 1 / candidates if candidates else 0.0


def binom_sf(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p), summed in log space so large n does not underflow."""
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    # The first term in log space, then each next one by the ratio of successive terms.
    term = exp(lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1) + k * log(p) + (n - k) * log(1 - p))
    total, ratio = 0.0, p / (1 - p)
    for i in range(k, n + 1):
        total += term
        term *= (n - i) / (i + 1) * ratio
    return min(1.0, total)


def critical_count(n: int, p0: float, alpha: float = ALPHA) -> int:
    """The smallest count c with P(X >= c | p0) <= alpha: the test rejects chance at c or more."""
    lo, hi = 0, n + 1
    while lo < hi:
        mid = (lo + hi) // 2
        if binom_sf(mid, n, p0) <= alpha:
            hi = mid
        else:
            lo = mid + 1
    return lo


def _power(n: int, p0: float, alpha: float) -> float:
    return binom_sf(critical_count(n, p0, alpha), n, 2 * p0)


def required_joins(p0: float, alpha: float = ALPHA, power: float = POWER) -> int | None:
    """The number of joins n at which the test detects precision 2*p0 with the given power.

    Found by doubling then bisection. Power is a sawtooth in n, so this is the smallest n the
    bisection lands on, not always the global minimum; it errs toward a larger control, never a
    smaller one. None when 2*p0 is not a precision (p0 > 0.5) or p0 is 0.
    """
    if p0 <= 0.0 or 2 * p0 > 1.0:
        return None
    hi = 8
    while _power(hi, p0, alpha) < power:
        hi *= 2
    lo = hi // 2
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if _power(mid, p0, alpha) >= power:
            hi = mid
        else:
            lo = mid
    return hi


def at_chance(correct: int, joins: int, base_rate: float, alpha: float = ALPHA) -> bool:
    """Whether `correct` right joins out of `joins` is consistent with guessing at `base_rate`."""
    return binom_sf(correct, joins, base_rate) > alpha
