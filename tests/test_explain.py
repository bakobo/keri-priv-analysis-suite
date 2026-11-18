"""Plain-language explanations (this.i 6r9sjucj): every name a report shows has one, and each
helper turns an id into words a reader outside the design review can follow."""

import re
import tomllib
from pathlib import Path

import pytest

from keri_priv_analysis import explain
from keri_priv_analysis.attacks import ATTACKS
from keri_priv_analysis.model import INSTANCE_KINDS, SINGLE_KINDS
from keri_priv_analysis.scenario import ACCESS_LOG_ROLES, METRICS, PARTY_KINDS

REPO = Path(__file__).resolve().parent.parent
SITE = explain.SITE


# Coverage: the suite cannot gain a name without an explanation.


def test_every_attack_has_a_title_and_summary():
    for name in ATTACKS:
        assert explain.attack_title(name) != name
        assert len(explain.attack_summary(name)) > 40


def test_every_party_kind_is_explained():
    for kind in PARTY_KINDS:
        assert explain.party_kind(kind).endswith(".")


def test_every_compartment_kind_is_explained():
    for kind in SINGLE_KINDS:
        assert explain.compartment(kind) != kind
    for kind in INSTANCE_KINDS:
        assert explain.compartment(kind) != kind
    for role in ACCESS_LOG_ROLES:
        assert explain.compartment(f"access-log:{role}") != f"access-log:{role}"


def test_every_metric_is_explained():
    for metric in METRICS:
        assert explain.claim(metric, "<=", 0.0)
        assert explain.claim(metric, ">=", 0.5)


def test_every_party_in_the_approved_scenarios_has_a_title():
    for scenario in (REPO / "scenarios").glob("privacy-*.toml"):
        for party in tomllib.loads(scenario.read_text())["party"]:
            assert explain.party_title(party["name"]) != party["name"], party["name"]


def test_every_glossary_anchor_a_term_links_to_exists():
    glossary = (REPO / "docs" / "glossary.md").read_text()
    headings = {explain.slug(h) for h in re.findall(r"^#+ (.+)$", glossary, re.MULTILINE)}
    for term in explain.data()["terms"].values():
        assert term["anchor"] in headings, term["anchor"]


# Wording.


def test_a_party_title_falls_back_to_its_id():
    assert explain.party_title("many-verifiers") == "Four colluding verifiers"
    assert explain.party_title("someone-new") == "someone-new"


@pytest.mark.parametrize("name, words", [
    ("public", "the public record"),
    ("verifier:liquor-store", "the liquor store's records"),
    ("issuing-home:3", "issuing home 3"),
    ("access-log:registrar", "the Registrar's access log"),
    ("verifier", "a verifier's records"),
    ("access-log", "an access log"),
    ("issuing-home", "an issuing home"),
    ("access-log:unheard-of", "access-log:unheard-of"),
    ("mystery", "mystery"),
])
def test_compartments_read_as_words(name, words):
    assert explain.compartment(name) == words


def test_a_compartment_links_to_the_glossary_with_what_it_holds_as_hover():
    assert explain.compartment_link("verifier:bar") == (
        f'[the bar\'s records]({SITE}glossary/#compartment "The records a verifier kept of the '
        'presentations it received.")')
    assert explain.compartment_link("mystery") == "mystery"


def test_what_an_attack_needs_reads_as_words():
    assert explain.needs("verifier") == "a verifier's records"
    assert explain.needs("access-log:observer or access-log:registrar") == (
        "the Observer's access log or the Registrar's access log")
    assert explain.needs("no Registrar batches") == "no Registrar batches"


def test_a_zero_claim_is_a_sentence():
    assert explain.claim("reidentified", "<=", 0.0) == (
        "re-identifies no simulated citizen, singling none out from the population")


@pytest.mark.parametrize("op, words", [
    ("<=", "at most"), (">=", "at least"), ("<", "less than"), (">", "more than"),
    ("==", "exactly")])
def test_any_other_claim_names_its_quantity(op, words):
    assert explain.claim("precision", op, 0.5) == (
        f"the share of its correlations that are correct is {words} 0.5")


def test_verdicts_read_as_words():
    assert explain.verdict("pass") == "holds"
    assert explain.verdict("fail") == "fails"
    assert explain.verdict("not-measured") == "not measured"
    assert explain.verdict("other") == "other"


def test_a_term_links_to_its_glossary_entry_with_hover_text():
    link = explain.term("precision", "Precision")
    assert link.startswith(f"[Precision]({SITE}glossary/#precision \"")
    assert link.endswith('")')


def test_an_attack_links_to_its_entry_with_hover_text():
    link = explain.attack_link("shared-registry")
    assert link.startswith(
        f"[Shared registry]({SITE}attacks/#shared-registry-shared-registry \"Two presented")


def test_an_unknown_attack_is_named_by_its_id():
    assert explain.attack_link("not-an-attack") == "not-an-attack"


def test_hover_text_never_breaks_a_link_title():
    assert explain.hover('He said "no" (twice)') == "He said 'no' (twice)"


@pytest.mark.parametrize("heading, anchor", [
    ("Correlation", "correlation"),
    ("Claim and verdict", "claim-and-verdict"),
    ("Re-identified", "re-identified"),
    ("Four colluding verifiers (many-verifiers)", "four-colluding-verifiers-many-verifiers"),
    ("A hacker in one issuing home, with the verifiers' records (one-home-with-verifiers)",
     "a-hacker-in-one-issuing-home-with-the-verifiers-records-one-home-with-verifiers"),
])
def test_slug_matches_the_sites_heading_anchors(heading, anchor):
    assert explain.slug(heading) == anchor


def test_the_committed_attacks_page_matches_the_catalogue():
    """docs/attacks.md is generated (scripts/attacks-page); a catalogue or explanation change
    without regenerating it fails here."""
    assert (REPO / "docs" / "attacks.md").read_text() == explain.attacks_page()
    page = explain.attacks_page()
    for name in ATTACKS:
        anchor = explain.slug(f"{explain.attack_title(name)} ({name})")
        assert explain.attack_link(name).split("#")[1].startswith(anchor + " ")
        assert f"## {explain.attack_title(name)} ({name})" in page
    assert "It tests the registry [correlation vector](glossary.md#correlation-vector)." in page
    assert "It tests the batch and AID [correlation vectors](glossary.md" in page
