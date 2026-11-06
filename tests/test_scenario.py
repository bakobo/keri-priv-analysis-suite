"""The scenario file (docs/test-plan.md Part B item 8)."""

import re
import tomllib
from pathlib import Path

import pytest
from bakobo.errors import BakoboError

from keri_priv_analysis.scenario import load, loads

SMOKE = Path(__file__).parent.parent / "scenarios" / "smoke.toml"
TEXT = SMOKE.read_text()


def _without(text, line_pattern):
    out, n = re.subn(line_pattern, "", text, count=1, flags=re.MULTILINE)
    assert n == 1, line_pattern
    return out


def _replace(text, old, new):
    assert old in text, old
    return text.replace(old, new, 1)


def test_the_smoke_scenario_loads_with_every_parameter():
    s = load(SMOKE)
    assert s.run.adapter == "generator"
    assert s.population.size == 3_500_000
    assert [a.name for a in s.population.attributes] == ["age-band", "county", "veteran"]
    assert s.citizens.count == 300 and s.citizens.copies == 6
    assert [p.name for p in s.parties] == ["colluding-verifiers", "home-hacker",
                                          "verifiers-buy-stolen-home"]
    assert s.stack.retention["issuing-home"] == float("inf")
    assert s.mandatory == {"alcohol": True, "pharmacy": False}
    assert s.compartment_names() >= {"public", "verifier:liquor-store", "issuing-home:0"}
    assert len(s.digest) == 64


def test_digest_is_of_the_file_bytes():
    assert loads(TEXT).digest == load(SMOKE).digest
    assert loads(TEXT + "\n").digest != load(SMOKE).digest


@pytest.mark.parametrize("pattern", [
    r"^seed = 20261117\n", r"^confidence_cut = .*\n", r"^homes = 4\n", r"^copies = 6\n",
    r"^dt_granularity = .*\n", r"^decoys = .*\n", r"^context_bits = .*\n", r"^mandatory = true\n",
    r"^sensitive = false\n", r"^rho = .*\n", r"^per_citizen = 2\n", r"^threshold = 0.0\n",
    r"^identity-proofing = inf\n",
])
def test_an_unset_parameter_is_refused(pattern):
    with pytest.raises(BakoboError) as raised:
        loads(_without(TEXT, pattern))
    assert raised.value.code == "e.input.missing.scenario-parameter.f"


def test_a_missing_section_is_refused():
    text = TEXT[:TEXT.index("[stack]")] + TEXT[TEXT.index("[[party]]"):]
    with pytest.raises(BakoboError) as raised:
        loads(text)
    assert raised.value.code == "e.input.missing.scenario-parameter.f"


def test_an_unknown_parameter_is_refused():
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, "decoys = 0\n", "decoys = 0\ndecoyz = 1\n"))
    assert raised.value.code == "e.input.format.scenario-parameter.f"


@pytest.mark.parametrize("old,new", [
    ('"issuing-home:0"]\nobtains_at', '"issuing-home:9"]\nobtains_at'),
    ('compartments = ["public", "verifier:liquor-store", "verifier:pharmacy"]',
     'compartments = ["public", "verifier:bookshop"]'),
    ('compartments = ["public", "verifier:liquor-store", "verifier:pharmacy"]',
     'compartments = ["public", "access-log:printer"]'),
    ('compartments = ["public", "verifier:liquor-store", "verifier:pharmacy"]',
     'compartments = ["publick"]'),
    ('terms = []\ncontext_bits = 0.0\n\n[[party]]\nname = "home-hacker"',
     'terms = ["verifier:nobody"]\ncontext_bits = 0.0\n\n[[party]]\nname = "home-hacker"'),
])
def test_an_unknown_compartment_is_refused(old, new):
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, old, new))
    assert raised.value.code in ("e.input.format.compartment-name.f",
                                 "e.input.range.scenario-compartment.f")


def test_access_log_roles_and_issuing_home_numbers_are_accepted():
    text = _replace(TEXT, 'compartments = ["public", "issuing-home:0"]',
                    'compartments = ["access-log:hosted-agent", "issuing-home:3", '
                    '"identity-proofing"]')
    assert loads(text).parties[1].compartments[0] == "access-log:hosted-agent"


def test_a_party_kind_outside_the_five_is_refused():
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, 'kind = "hacker"', 'kind = "journalist"'))
    assert raised.value.code == "e.input.range.scenario-party-kind.f"


def test_terms_on_a_compelling_government_party_are_refused():
    text = _replace(TEXT, 'kind = "colluding-verifier"', 'kind = "government"')
    loads(text)  # no terms: fine
    text = _replace(text, 'terms = []', 'terms = ["verifier:pharmacy"]')
    with pytest.raises(BakoboError) as raised:
        loads(text)
    assert raised.value.code == "e.input.multi.scenario-government-terms.f"


@pytest.mark.parametrize("old,new,code", [
    ('registry_scope = "credential"', 'registry_scope = "household"',
     "e.input.range.scenario-parameter.f"),
    ('adapter = "generator"', 'adapter = "fabric"', "e.input.range.scenario-parameter.f"),
    ('metric = "reidentified"', 'metric = "vibes"', "e.input.range.scenario-parameter.f"),
    ('op = "<="', 'op = "~"', "e.input.range.scenario-parameter.f"),
    ('party = "colluding-verifiers"\nmetric', 'party = "nobody"\nmetric',
     "e.input.range.scenario-parameter.f"),
    ('verifier = "pharmacy"\ndomain', 'verifier = "bank"\ndomain',
     "e.input.range.scenario-parameter.f"),
    ('domain = "pharmacy"\ndisclose', 'domain = "casino"\ndisclose',
     "e.input.range.scenario-parameter.f"),
    ('disclose = ["age-band"]', 'disclose = ["shoe-size"]', "e.input.range.scenario-parameter.f"),
    ("copies = 6", 'copies = "six"', "e.input.format.scenario-parameter.f"),
    ("copies = 6", "copies = 0", "e.input.range.scenario-parameter.f"),
    ("confidence_cut = 1.0", "confidence_cut = 1.5", "e.input.range.scenario-parameter.f"),
    ("end = 5184000.0", "end = 1.0", "e.input.range.scenario-parameter.f"),
    ("per_citizen = 2\nstart", "per_citizen = 9\nstart", "e.input.range.scenario-parameter.f"),
    ("sensitive = false", 'sensitive = "no"', "e.input.format.scenario-parameter.f"),
    ("decoys = 0", "decoys = 1.5", "e.input.format.scenario-parameter.f"),
    ("rho = 0.3", "rho = true", "e.input.format.scenario-parameter.f"),
    ('[[verifier]]\nid = "pharmacy"', '[[verifier]]\nid = "liquor-store"',
     "e.input.multi.scenario-name.f"),
])
def test_out_of_range_or_mistyped_values_are_refused(old, new, code):
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, old, new))
    assert raised.value.code == code


def test_a_scenario_that_is_not_toml_is_refused():
    with pytest.raises(BakoboError) as raised:
        loads("this is = = not toml")
    assert raised.value.code == "e.input.format.scenario.f"


def test_a_scenario_too_large_is_refused_before_it_is_parsed():
    with pytest.raises(BakoboError) as raised:
        loads("#" * (2 * 1024 * 1024))
    assert raised.value.code == "e.input.range.scenario-size.f"


def test_the_population_spec_round_trips():
    s = load(SMOKE)
    spec = s.population_spec()
    assert spec.size == 3_500_000 and spec.homes == 4
    assert spec.correlations[0].rho == 0.3
    assert tomllib.loads(TEXT)["population"]["seed"] == spec.seed


def test_a_presentation_window_opening_before_issuance_ends_is_refused():
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, "start = 2678400.0", "start = 0.0"))
    assert raised.value.code == "e.input.range.scenario-parameter.f"


def test_only_retention_may_be_infinite():
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, "threshold = 0.0", "threshold = inf"))
    assert raised.value.code == "e.input.format.scenario-parameter.f"
    with pytest.raises(BakoboError):
        loads(_replace(TEXT, "public = inf", "public = nan"))


@pytest.mark.parametrize("old,new", [
    ('name = "home-hacker"', 'name = "/tmp/hostile"'),
    ('name = "home-hacker"', 'name = "Home-Hacker"'),
    ('id = "pharmacy"', 'id = "../pharmacy"'),
    ('name = "alcohol"', 'name = "alcohol domain"'),
])
def test_names_that_reach_compartment_or_file_names_must_be_slugs(old, new):
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, old, new))
    assert raised.value.code == "e.input.range.scenario-parameter.f"


def test_a_window_must_open_after_the_last_copy_could_be_issued():
    # The last session may open just before the period ends and take copies * interval more.
    with pytest.raises(BakoboError):
        loads(_replace(TEXT, "copy_interval = 0.004", "copy_interval = 100000.0"))
    loads(_replace(TEXT, "copy_interval = 0.004", "copy_interval = 0.0"))


@pytest.mark.parametrize("old,new", [("public = inf", "public = " + "9" * 400),
                                     ("copies = 6", "copies = " + "9" * 400),
                                     ("rho = 0.3", "rho = " + "9" * 400)])
def test_numbers_too_large_to_mean_anything_are_refused_with_a_code(old, new):
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, old, new))
    assert raised.value.code == "e.input.format.scenario-parameter.f"


@pytest.mark.parametrize("bad", ["nan", "9" * 400, "inf", "1e308"])
def test_every_number_in_a_list_is_bounded_too(bad):
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, "probabilities = [0.93, 0.07]", f"probabilities = [0.93, {bad}]"))
    assert raised.value.code == "e.input.format.scenario-parameter.f"


def test_a_time_beyond_the_clock_is_refused():
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, "issuance_period = 2592000.0", "issuance_period = 1e308"))
    assert raised.value.code == "e.input.format.scenario-parameter.f"


def test_a_window_must_also_leave_time_to_admit_the_last_copy():
    with pytest.raises(BakoboError):
        loads(TEXT.replace("start = 2678400.0", "start = 2592010.0"))


@pytest.mark.parametrize("old,new,code", [
    ("copies = 6", "copies = " + "9" * 5000, "e.input.format.scenario.f"),
    ("dt_granularity = 0.0", "dt_granularity = 1e-310", "e.input.range.scenario-parameter.f"),
    ("publication_window = 0.0", "publication_window = 1e-9",
     "e.input.range.scenario-parameter.f"),
    ("copy_interval = 0.004", "copy_interval = 1e10", "e.input.range.scenario-parameter.f"),
])
def test_values_the_clock_or_the_parser_cannot_take_are_refused_with_codes(old, new, code):
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, old, new))
    assert raised.value.code == code


def test_a_population_too_big_to_hold_and_deeply_nested_toml_are_refused():
    with pytest.raises(BakoboError) as raised:
        loads(_replace(TEXT, "size = 3500000", "size = 60000000"))
    assert raised.value.code == "e.input.range.scenario-parameter.f"
    with pytest.raises(BakoboError) as raised:
        loads("a = " + "{b=" * 2000 + "1" + "}" * 2000)
    assert raised.value.code == "e.input.format.scenario.f"
