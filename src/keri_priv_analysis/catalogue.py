"""The catalogue's coverage mapping and the owners file, read from the package's data."""

from __future__ import annotations

import tomllib
from functools import cache
from importlib.resources import files


@cache
def mapping() -> dict:
    return tomllib.loads(files(__package__).joinpath("data/catalogue.toml").read_text())


@cache
def owners() -> dict[str, str]:
    return tomllib.loads(files(__package__).joinpath("data/owners.toml").read_text())


def non_claims() -> list[str]:
    return mapping()["non-claims"]["items"]


def gaps() -> dict[str, str]:
    """Tick id -> an attack the catalogue does not yet make."""
    return mapping()["gaps"]
