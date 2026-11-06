"""Catalogue coverage (docs/test-plan.md Part B item 7)."""

import dataclasses
import re

import pytest

from keri_priv_analysis.attacks import ATTACKS, CATALOGUE
from keri_priv_analysis.catalogue import gaps, mapping, non_claims, owners
from keri_priv_analysis.population import PopulationSpec
from keri_priv_analysis.scenario import Stack

VECTORS = ("registry", "timestamp", "batch", "AID", "network")
FINDINGS = ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F-J180", "F-CVNP")
COUNTERMEASURES = (  # this.i 2gxskju4 and 8zuzm3v3, plus blinded bup from the test plan
    "random registry allocation", "mixing issuance order across citizens", "coarse dt",
    "identity oracle", "decoy registries and records",
    "revocation map sealed away from the issuing home", "retention expiry", "blinded bup",
    "batch commitment", "Registrar batch windows", "fleet size across issuing homes",
)


def _answered(names):
    return [n for n in names if n in ATTACKS or n in non_claims()]


@pytest.mark.parametrize("vector", VECTORS)
def test_each_vector_maps_to_an_attack_and_agrees_with_the_attacks(vector):
    named = mapping()["vectors"][vector]
    assert _answered(named) == named and named
    assert set(named) == {a.name for a in CATALOGUE if vector in a.vectors}


@pytest.mark.parametrize("finding", FINDINGS)
def test_each_finding_maps_to_an_attack(finding):
    named = mapping()["findings"][finding]
    assert named and _answered(named) == named
    assert all(finding in ATTACKS[n].origin for n in named)


def test_every_attack_origin_is_a_finding_or_a_named_source():
    for attack in CATALOGUE:
        for origin in attack.origin:
            assert origin in FINDINGS or " " in origin


@pytest.mark.parametrize("countermeasure", COUNTERMEASURES)
def test_each_countermeasure_maps_to_a_scenario_setting(countermeasure):
    settings = mapping()["countermeasures"][countermeasure]
    stack = {f.name for f in dataclasses.fields(Stack)}
    population = {f.name for f in dataclasses.fields(PopulationSpec)}
    for setting in settings:
        section, _, name = setting.partition(".")
        assert name in {"stack": stack, "population": population}[section], setting


def test_the_mapping_names_nothing_extra():
    assert set(mapping()) == {"vectors", "findings", "countermeasures", "non-claims", "gaps"}
    assert set(mapping()["vectors"]) == set(VECTORS)
    assert set(mapping()["findings"]) == set(FINDINGS)
    assert set(mapping()["countermeasures"]) == set(COUNTERMEASURES)


@pytest.mark.parametrize("attack", CATALOGUE, ids=lambda a: a.name)
def test_each_attack_has_both_controls_and_an_owner(attack):
    assert isinstance(attack.positive, dict) and isinstance(attack.negative, dict)
    assert attack.positive != attack.negative
    assert owners()[attack.name]


def test_non_claims_are_the_test_plans_five():
    assert len(non_claims()) == 5
    assert "breach detection" in non_claims()


def test_every_gap_names_a_tick():
    assert gaps()
    for tick, text in gaps().items():
        assert re.fullmatch(r"[2-7][a-z2-7]{3}", tick) and text
