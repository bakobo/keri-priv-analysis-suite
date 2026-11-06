"""The population model: a table of P rows from declared marginals and correlations.

Bits are scored against it (this.i 8q5ylk4q). Correlations are those of a Gaussian copula: each
attribute is a latent standard normal, the latents are correlated as declared, and each latent is
cut into categories at the quantiles its marginal implies. Simulated citizens are rows of this
table, so a citizen always matches at least one row and bits never exceed log2(P).

The issuing home is a derived column, "issuing-home": uniform at random over the homes, or, when
homes are sharded by an attribute, that attribute's value index modulo the number of homes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from math import log2
from statistics import NormalDist

import numpy as np

from . import errors

HOME = "issuing-home"
_CHUNK = 1 << 20


@dataclass(frozen=True)
class Attribute:
    name: str
    values: tuple[str, ...]
    probabilities: tuple[float, ...]
    sensitive: bool


@dataclass(frozen=True)
class Correlation:
    a: str
    b: str
    rho: float


@dataclass(frozen=True)
class PopulationSpec:
    size: int
    seed: int
    attributes: tuple[Attribute, ...]
    correlations: tuple[Correlation, ...]
    homes: int
    home_assignment: str  # "uniform", or the name of the attribute homes are sharded by


class Population:
    def __init__(self, spec: PopulationSpec, codes: dict[str, np.ndarray]):
        self.spec = spec
        self.size = spec.size
        self.codes = codes
        self.values = {a.name: a.values for a in spec.attributes}
        self.values[HOME] = tuple(str(h) for h in range(spec.homes))
        self.sensitive = tuple(a.name for a in spec.attributes if a.sensitive)
        self.max_bits = log2(self.size)
        self._tables: dict[tuple[str, ...], dict[int, int]] = {}

    def row(self, i: int) -> dict[str, str]:
        return {name: self.values[name][int(col[i])] for name, col in self.codes.items()}

    def _code(self, name: str, value: str) -> int:
        if name not in self.values:
            raise errors.POPULATION_ATTRIBUTE(name=name)
        if value not in self.values[name]:
            raise errors.POPULATION_VALUE(name=name, value=value)
        return self.values[name].index(value)

    def match_count(self, attrs: dict[str, str]) -> int:
        """The number of rows matching every attribute given.

        Counts are tabulated once per set of attribute names, as a histogram over the rows'
        combined codes, because a run asks this for every cluster of every citizen.
        """
        names = tuple(sorted(attrs))
        key = 0
        for name in names:
            code = self._code(name, attrs[name])
            key = key * len(self.values[name]) + code
        if names not in self._tables:
            combined = np.zeros(self.size, dtype=np.int64)
            for name in names:
                combined = combined * len(self.values[name]) + self.codes[name]
            keys, counts = np.unique(combined, return_counts=True)
            self._tables[names] = dict(zip(keys.tolist(), counts.tolist(), strict=True))
        return self._tables[names].get(key, 0)

    def bits(self, attrs: dict[str, str]) -> float:
        """log2(P / m), where m is the number of rows matching every attribute given."""
        if not attrs:
            return 0.0
        return log2(self.size / self.match_count(attrs))

    def digest(self) -> str:
        h = hashlib.sha256()
        for name in sorted(self.codes):
            h.update(name.encode() + b"\0" + self.codes[name].tobytes())
        return h.hexdigest()


def _validate(spec: PopulationSpec) -> list[str]:
    if spec.size < 1:
        raise errors.POPULATION_SIZE(size=spec.size)
    if spec.homes < 1:
        raise errors.POPULATION_HOMES(homes=spec.homes)
    names = []
    for a in spec.attributes:
        if a.name in names:
            raise errors.POPULATION_ATTRIBUTE_DUPLICATE(name=a.name)
        names.append(a.name)
        total = sum(a.probabilities)
        if len(a.values) != len(a.probabilities) or abs(total - 1.0) > 1e-9:
            raise errors.POPULATION_MARGINAL(name=a.name, values=len(a.values),
                                             probabilities=len(a.probabilities), total=total)
    for c in spec.correlations:
        for name in (c.a, c.b):
            if name not in names:
                raise errors.POPULATION_ATTRIBUTE(name=name)
        if not -1.0 <= c.rho <= 1.0:
            raise errors.POPULATION_CORRELATION(
                reason=f"The correlation between {c.a} and {c.b} is {c.rho}, outside [-1, 1].")
    if spec.home_assignment != "uniform" and spec.home_assignment not in names:
        raise errors.POPULATION_ATTRIBUTE(name=spec.home_assignment)
    return names


def generate(spec: PopulationSpec) -> Population:
    names = _validate(spec)
    k = len(names)
    corr = np.eye(k)
    for c in spec.correlations:
        i, j = names.index(c.a), names.index(c.b)
        corr[i, j] = corr[j, i] = c.rho
    try:
        lower = np.linalg.cholesky(corr)
    except np.linalg.LinAlgError:
        raise errors.POPULATION_CORRELATION(
            reason="The declared correlations do not form a positive definite matrix.") from None
    cuts = [np.array([NormalDist().inv_cdf(min(max(q, 1e-15), 1 - 1e-15))
                      for q in np.cumsum(a.probabilities)[:-1]]) for a in spec.attributes]
    codes = {name: np.empty(spec.size, dtype=np.uint16) for name in names}
    rng = np.random.default_rng(spec.seed)
    for start in range(0, spec.size, _CHUNK):
        stop = min(start + _CHUNK, spec.size)
        latent = rng.standard_normal((stop - start, k)) @ lower.T
        for i, name in enumerate(names):
            codes[name][start:stop] = np.searchsorted(cuts[i], latent[:, i])
    if spec.home_assignment == "uniform":
        home_rng = np.random.default_rng([spec.seed, 1])
        codes[HOME] = home_rng.integers(0, spec.homes, size=spec.size).astype(np.uint16)
    else:
        codes[HOME] = (codes[spec.home_assignment] % spec.homes).astype(np.uint16)
    return Population(spec, codes)
