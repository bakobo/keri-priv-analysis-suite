from pathlib import Path

import pytest
from keri_priv_analysis.population import generate
from keri_priv_analysis.scenario import load

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


@pytest.fixture(scope="session")
def scenario():
    return load(ROOT / "scenarios" / "contract.toml")


@pytest.fixture(scope="session")
def population(scenario):
    return generate(scenario.population)
