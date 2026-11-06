"""The report (docs/test-plan.md Part B item 9): golden output on a hand-built run, no claim of
unlinkability, and the non-claims always present."""

import copy
import json
from pathlib import Path

import pytest
from bakobo.errors import BakoboError

from keri_priv_analysis import report
from keri_priv_analysis.catalogue import non_claims

GOLDEN = Path(__file__).parent / "golden"


def _score(**overrides):
    base = {"threshold_bits": 4.322, "joins": 3, "direct_correct": 2, "certain_share": 1.0,
            "precision": 0.667, "recall": 0.5, "bits": [1.0, 2.5, 4.322], "reidentified": 1,
            "sensitive_exposed": {"veteran": 1}, "identity_exposed": 1, "bound_joins": 2,
            "breach_bits": [4.322, 4.322, 4.322], "breach_reidentified": 3,
            "increment": [0.0, 0.5, 2.322],
            "completeness": {"alcohol": {"0": 1.0, "1": 0.5, "2": 0.0}, "pharmacy": {}},
            "flagged": {"alcohol": True}}
    base.update(overrides)
    return base


RESULTS = {
    "provenance": {"suite": "2026.10", "python": "3.14.6",
                   "keripy": {"version": "2.1.0.dev1", "commit": ""},
                   "scenario_sha256": "ab" * 32,
                   "population": {"seed": 1, "size": 20, "sha256": "cd" * 32},
                   "adapter": {"name": "generator"}},
    "causes": {"timestamp-clustering": "microsecond dt"},
    "owners": {"timestamp-clustering": "the issuer", "log-scan": "everyone"},
    "parties": {
        "verifiers": {
            "kind": "colluding-verifier",
            "compartments": {"public": "present", "verifier:v1": "present",
                             "orchestrator": "absent"},
            "notes": {"orchestrator": "Not built yet."},
            "attacks": {
                "timestamp-clustering": {"measured": True, "joins": 3, "observations": 0,
                                         "score": _score()},
                "issuer-aid-bucket": {"measured": True, "joins": 0, "observations": 6,
                                      "score": _score(precision=None, certain_share=None,
                                                      reidentified=0)},
                "hosted-agent": {"measured": False, "missing": ["access-log:hosted-agent"]},
            },
            "score": _score(),
        },
        "hacker": {"kind": "hacker", "compartments": {"issuing-home:0": "present"},
                   "notes": {}, "attacks": {},
                   "score": _score(bits=[], increment=[], sensitive_exposed={},
                                   completeness={}, flagged={}, precision=None, recall=None)},
    },
    "claims": [
        {"party": "verifiers", "metric": "reidentified", "op": "<=", "threshold": 0.0,
         "verdict": "fail", "measured": 1, "attacks": ["timestamp-clustering", "log-scan"]},
        {"party": "verifiers", "metric": "max_bits", "op": "<=", "threshold": 10.0,
         "verdict": "pass", "measured": 4.322, "attacks": []},
        {"party": "hacker", "metric": "flagged_domains", "op": "<=", "threshold": 0.0,
         "verdict": "fail", "measured": 1, "attacks": []},
        {"party": "hacker", "metric": "precision", "op": ">=", "threshold": 0.5,
         "verdict": "not-measured", "measured": None, "attacks": []},
    ],
}


def _write(tmp_path, results):
    (tmp_path / "results.json").write_text(json.dumps(results))
    report.write(tmp_path)
    return (tmp_path / "report.md").read_text(), json.loads((tmp_path / "report.json").read_text())


def test_golden_report(tmp_path):
    text, summary = _write(tmp_path, RESULTS)
    assert text == (GOLDEN / "report.md").read_text()
    assert summary == json.loads((GOLDEN / "report.json").read_text())


def test_the_report_never_claims_unlinkability_and_always_ends_with_the_non_claims(tmp_path):
    text, summary = _write(tmp_path, RESULTS)
    assert "unlinkab" not in text.lower()
    gaps = text[text.index("## Attacks the catalogue does not yet make"):]
    assert "(tick 5sdj)" in gaps
    tail = text[text.index("## What this report does not claim"):]
    for item in non_claims():
        assert f"- {item}" in tail
    assert summary["non_claims"] == non_claims()


@pytest.mark.parametrize("where", ["party", "cause"])
def test_a_report_that_would_say_unlinkable_is_refused(tmp_path, where):
    results = copy.deepcopy(RESULTS)
    if where == "party":
        results["parties"]["Unlinkable-Fans"] = results["parties"].pop("hacker")
    else:
        results["causes"]["timestamp-clustering"] = "copies are unlinkable"
    with pytest.raises(BakoboError) as raised:
        _write(tmp_path, results)
    assert raised.value.code == "e.rule.report-word.f"
    assert not (tmp_path / "report.md").exists()


def test_number_formatting():
    assert report._n(None) == "not measured"
    assert report._n(2.0) == "2"
    assert report._n(0.1234) == "0.123"
    assert report._n(7) == "7"
    assert report._quantile([], 0.9) == 0.0


def test_a_run_with_no_failing_claim_has_no_failures_section(tmp_path):
    results = copy.deepcopy(RESULTS)
    results["claims"] = [c for c in results["claims"] if c["verdict"] != "fail"]
    text, _ = _write(tmp_path, results)
    assert "## Failures" not in text and "## Claims" in text


def test_report_states_adapter_measurement_limits(tmp_path):
    results = copy.deepcopy(RESULTS)
    results["provenance"]["adapter"]["limitations"] = [
        "Verifier-side bits are a lower bound because birthDate is visible in full."]
    text, summary = _write(tmp_path, results)
    assert "## Measurement limits" in text
    assert "Verifier-side bits are a lower bound because birthDate is visible in full." in text
    assert summary["provenance"]["adapter"]["limitations"] == results[
        "provenance"]["adapter"]["limitations"]
    assert len(summary["measurement_limits"]) == 1
    assert text.count("- Verifier-side bits are a lower bound") == 1


def test_verifier_bits_limit_is_in_every_report(tmp_path):
    text, summary = _write(tmp_path, RESULTS)
    expected = ("Verifier-side bits are a lower bound on what presentation bytes can reveal: "
                "the scorer counts declared attributes, while a selectively disclosed age-band "
                "presentation can carry a full birthDate (tick 6hat).")
    assert expected in summary["measurement_limits"]
    assert f"- {expected}" in text
