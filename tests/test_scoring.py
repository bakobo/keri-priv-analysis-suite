"""The scorer (docs/test-plan.md Part B item 3). Expected values are derived here, by hand."""

from math import log2

import numpy as np
import pytest

from keri_priv_analysis.model import (
    Compartment,
    CompartmentSet,
    GroundTruth,
    Join,
    Observation,
    Presentation,
)
from keri_priv_analysis.population import HOME, Attribute, Population, PopulationSpec
from keri_priv_analysis.scoring import PartyTerms, score

# Twenty rows. Row 0 is (x, 1, yes); row 1 is (x, 1, no); rows 2-9 are (x, 2, no); row 10 is
# (y, 3, yes) and rows 11-19 are (y, 3, no). So a=x matches 10 rows, a=x b=1 matches 2, c=yes
# matches 2, and a=x b=1 c=yes matches only row 0.
ROWS = ([("x", "1", "yes"), ("x", "1", "no")] + [("x", "2", "no")] * 8 + [("y", "3", "yes")]
        + [("y", "3", "no")] * 9)


def _population():
    attrs = (Attribute("a", ("x", "y"), (0.5, 0.5), False),
             Attribute("b", ("1", "2", "3"), (0.1, 0.4, 0.5), False),
             Attribute("c", ("no", "yes"), (0.95, 0.05), True))
    spec = PopulationSpec(size=20, seed=0, attributes=attrs, correlations=(), homes=2,
                          home_assignment="uniform")
    codes = {a.name: np.array([a.values.index(r[i]) for r in ROWS], dtype=np.uint16)
             for i, a in enumerate(attrs)}
    codes[HOME] = np.array([i % 2 for i in range(20)], dtype=np.uint16)
    return Population(spec, codes)


def _p(handle, verifier, disclosed, domain="shop", time=0.0):
    return Presentation(handle=handle, verifier=verifier, time=time, domain=domain,
                        disclosed=disclosed, said="E" + handle, registry="R" + handle,
                        issuer="I", holder="H" + handle, raw=b"")


# Citizen 0 is row 0, citizen 1 is row 1, citizen 2 is row 10.
# v1 holds p1 (c0: a,b), p3 (c1: a,b), p5 (c2: a). v2 holds p2 (c0: c), p4 (c1: c), p6 (c0: a).
V1 = [_p("p1", "v1", {"a": "x", "b": "1"}), _p("p3", "v1", {"a": "x", "b": "1"}),
      _p("p5", "v1", {"a": "y"})]
V2 = [_p("p2", "v2", {"c": "yes"}), _p("p4", "v2", {"c": "no"}), _p("p6", "v2", {"a": "x"})]
TRUTH = GroundTruth(citizen_rows=[0, 1, 10],
                    presentations={"p1": 0, "p2": 0, "p6": 0, "p3": 1, "p4": 1, "p5": 2},
                    identities={"r0": 0, "r1": 1}, artifacts={"Ep1": 0, "Ep3": 1},
                    domains={"p1": "shop", "p2": "shop", "p6": "shop", "p3": "shop",
                             "p4": "shop", "p5": "shop"})
HELD = CompartmentSet([Compartment(name="verifier:v1", status="present", presentations=V1),
                       Compartment(name="verifier:v2", status="present", presentations=V2)])
NO_TERMS = PartyTerms(kind="colluding-verifier", terms=frozenset(), context_bits=0.0)


def _score(joins, observations=(), terms=NO_TERMS, cut=1.0, held=HELD, mandatory=None):
    return score(terms, held, list(joins), list(observations), TRUTH, _population(), cut=cut,
                 mandatory=mandatory or {"shop": False})


def test_no_joins_leaves_each_citizen_at_their_best_single_presentation():
    s = _score([])
    assert s.bits == pytest.approx([log2(20 / 2), log2(20 / 2), log2(20 / 10)])
    assert s.reidentified == 0
    assert s.joins == 0 and s.precision is None


def test_a_second_join_crosses_the_threshold():
    s = _score([Join("p:p1", "p:p2", 1.0, "t")])
    assert s.bits[0] == pytest.approx(log2(20))
    assert s.reidentified == 1
    assert s.sensitive_exposed == {"c": 1}


def test_joins_compose_through_a_third_presentation():
    # p6 -- p1 and p1 -- p2 put p2 and p6 in one cluster though nobody joined them directly.
    s = _score([Join("p:p6", "p:p1", 1.0, "t"), Join("p:p1", "p:p2", 1.0, "t")])
    assert s.precision == 1.0
    # A redundant join inside the cluster, and one to a node nobody issued, change nothing.
    again = _score([Join("p:p6", "p:p1", 1.0, "t"), Join("p:p1", "p:p2", 1.0, "t"),
                    Join("p:p2", "p:p6", 1.0, "t"), Join("p:p2", "x:Enobody", 1.0, "t")])
    assert again.precision == 1.0 and again.bits == s.bits
    # Same-citizen pairs held: c0 has 3 presentations (3 pairs), c1 has 2 (1 pair): 4 in all.
    # The cluster {p1, p2, p6} recovers all 3 of c0's pairs.
    assert s.recall == pytest.approx(3 / 4)


def test_a_false_join_costs_precision_and_adds_no_bits():
    s = _score([Join("p:p1", "p:p4", 1.0, "t")])
    assert s.precision == 0.0
    assert s.bits[0] == pytest.approx(log2(10))  # c0 does not gain c1's "c=no"
    assert s.bits[1] == pytest.approx(log2(10))


def test_closure_precision_counts_pairs_inside_clusters():
    # Cluster {p1, p2, p4}: pairs (p1,p2) right, (p1,p4) and (p2,p4) wrong.
    s = _score([Join("p:p1", "p:p2", 1.0, "t"), Join("p:p2", "p:p4", 1.0, "t")])
    assert s.precision == pytest.approx(1 / 3)
    assert s.direct_correct == 1 and s.joins == 2


def test_joins_below_the_cut_are_ignored_and_certainty_is_reported():
    joins = [Join("p:p1", "p:p2", 0.6, "t"), Join("p:p3", "p:p4", 1.0, "t")]
    s = _score(joins, cut=0.9)
    assert s.joins == 1
    assert s.bits[0] == pytest.approx(log2(10))
    assert _score(joins, cut=0.5).certain_share == 0.5


def test_an_identity_join_is_full_reidentification():
    s = _score([Join("p:p5", "id:r0", 1.0, "t")])  # wrong: p5 is c2's
    assert s.bits[2] == pytest.approx(log2(2))
    s = _score([Join("p:p5", "x:Ep1", 1.0, "t"), Join("x:Ep1", "id:r0", 1.0, "t"),
                Join("p:p1", "id:r0", 1.0, "t")])
    assert s.bits[0] == pytest.approx(log2(20))
    assert s.identity_exposed == 1


def test_identity_records_without_presentations_count_as_custodial_exposure_only():
    s = _score([Join("x:Ep3", "id:r1", 1.0, "t"), Join("x:Ep1", "id:r1", 1.0, "t")])
    assert s.identity_exposed == 1  # only Ep3 truly belongs to r1's citizen
    assert s.reidentified == 0


def test_observations_add_only_their_true_value():
    # Row 0's home is 0 (i % 2). a=x, b=1, home=0 matches only row 0.
    s = _score([], [Observation("p:p1", HOME, "0", "t")])
    assert s.bits[0] == pytest.approx(log2(20))
    s = _score([], [Observation("p:p1", HOME, "1", "t")])
    assert s.bits[0] == pytest.approx(log2(10))


def test_bound_joins_leave_the_harm_totals_and_are_reported_apart():
    bound = PartyTerms(kind="colluding-verifier", terms=frozenset({"verifier:v2"}),
                       context_bits=0.0)
    s = _score([Join("p:p1", "p:p2", 1.0, "t"), Join("p:p1", "p:p6", 1.0, "t")], terms=bound)
    assert s.bound_joins == 2
    assert s.reidentified == 0
    assert s.breach_reidentified == 1
    assert s.breach_bits[0] == pytest.approx(log2(20))


def test_a_government_party_is_never_bound():
    gov = PartyTerms(kind="government", terms=frozenset({"verifier:v2"}), context_bits=0.0)
    s = _score([Join("p:p1", "p:p2", 1.0, "t")], terms=gov)
    assert s.bound_joins == 0 and s.reidentified == 1


def test_protocol_increment_subtracts_context_and_floors_at_zero():
    ctx = PartyTerms(kind="colluding-verifier", terms=frozenset(), context_bits=2.0)
    s = _score([Join("p:p1", "p:p2", 1.0, "t")], terms=ctx)
    assert s.increment == pytest.approx([log2(20) - 2, log2(10) - 2, 0.0])


def test_completeness_and_its_flag():
    # c0 has three shop events (p1, p2, p6). Holding all three in one certain cluster is total.
    joins = [Join("p:p1", "p:p2", 1.0, "t"), Join("p:p2", "p:p6", 1.0, "t")]
    s = _score(joins, mandatory={"shop": True})
    assert s.completeness["shop"][0] == 1.0
    assert s.completeness["shop"][1] == pytest.approx(0.5)
    assert s.flagged == {"shop": True}
    # Not certain: flagged only when every join in the cluster is certain.
    shaky = [Join("p:p1", "p:p2", 0.95, "t"), Join("p:p2", "p:p6", 1.0, "t")]
    assert _score(shaky, cut=0.9).flagged == {}
    # A party holding only v1 has one of c0's events: one event of three.
    only_v1 = HELD.subset(["verifier:v1"])
    s = _score([], held=only_v1)
    assert s.completeness["shop"][0] == pytest.approx(1 / 3)
    assert s.flagged == {}


def test_a_flag_records_whether_mandatory_use_was_off():
    joins = [Join("p:p1", "p:p2", 1.0, "t"), Join("p:p2", "p:p6", 1.0, "t")]
    assert _score(joins).flagged == {"shop": False}


def test_citizens_with_no_held_presentations_score_zero():
    only_v2 = HELD.subset(["verifier:v2"])
    s = _score([], held=only_v2)
    assert s.bits[2] == 0.0
    assert s.completeness["shop"][2] == 0.0


def test_score_serializes():
    d = _score([Join("p:p1", "p:p2", 1.0, "t")]).to_json()
    assert d["reidentified"] == 1 and d["threshold_bits"] == pytest.approx(log2(20))


def test_a_join_through_an_identifier_only_a_bound_compartment_holds_is_bound():
    from keri_priv_analysis.model import LogLine
    wide = "E" + "w" * 43  # an identifier of real length, which only this log carries
    log = Compartment(name="issuing-home:0", status="present",
                      logs=[LogLine(0.0, "10.0.0.1", f"credential {wide}")],
                      records={"iar": [{"record": "r0", "management": "M"}],
                               "pool": [{"said": "Ep1"}]})
    held = CompartmentSet([*HELD, log])
    bound = PartyTerms(kind="hacker", terms=frozenset({"issuing-home:0"}), context_bits=0.0)
    s = score(bound, held, [Join("x:Ep1", "id:r0", 1.0, "t"), Join("p:p1", "p:p2", 1.0, "t"),
                            Join(f"x:{wide}", "p:p3", 1.0, "t")],
              [], TRUTH, _population(), cut=1.0, mandatory={"shop": False})
    assert s.bound_joins == 2
