"""The compartment interface (this.i 9wxr29dq): names, statuses, contents, and the run directory."""

import dataclasses

import pytest
from bakobo.errors import BakoboError

from keri_priv_analysis import rundir
from keri_priv_analysis.model import (
    Compartment,
    CompartmentSet,
    GroundTruth,
    Knowledge,
    LogLine,
    Presentation,
    parse_compartment_name,
)


def _presentation(handle="p1", verifier="v1"):
    return Presentation(
        handle=handle, verifier=verifier, time=12.5, domain="alcohol",
        disclosed={"age-band": "21-29"}, said="Esaid", registry="Ereg", issuer="Eiss",
        holder="Ehold", raw=b"{\"v\":\"ACDC\"}-AAB",
    )


def test_compartment_names_parse_into_kind_and_instance():
    assert parse_compartment_name("public") == ("public", None)
    assert parse_compartment_name("verifier:v1") == ("verifier", "v1")
    assert parse_compartment_name("access-log:observer") == ("access-log", "observer")


@pytest.mark.parametrize("name", ["nonsense", "verifier", "public:x", "verifier:", "access-log:"])
def test_unknown_or_malformed_compartment_names_are_refused_with_a_code(name):
    with pytest.raises(BakoboError) as raised:
        parse_compartment_name(name)
    assert raised.value.code == "e.input.format.compartment-name.f"


def test_status_must_be_one_of_three():
    with pytest.raises(BakoboError) as raised:
        Compartment(name="public", status="empty")
    assert raised.value.code == "e.input.range.compartment-status.f"


def test_an_absent_or_unmeasured_compartment_carries_no_contents():
    with pytest.raises(BakoboError) as raised:
        Compartment(name="orchestrator", status="absent", logs=[LogLine(1.0, "10.0.0.1", "x")])
    assert raised.value.code == "e.input.multi.compartment-contents.f"
    Compartment(name="orchestrator", status="not-measured")


def test_compartment_set_lookup_by_kind_and_refuses_duplicates():
    a = Compartment(name="verifier:v1", status="present", presentations=[_presentation()])
    b = Compartment(name="verifier:v2", status="present")
    c = Compartment(name="public", status="present", streams={"kel:Eiss": b"x"})
    cs = CompartmentSet([a, b, c])
    assert [x.name for x in cs.of_kind("verifier")] == ["verifier:v1", "verifier:v2"]
    assert cs["public"] is c
    assert "public" in cs and "orchestrator" not in cs
    assert [x.name for x in cs] == ["verifier:v1", "verifier:v2", "public"]
    assert [p.handle for p in cs.presentations()] == ["p1"]
    with pytest.raises(BakoboError) as raised:
        CompartmentSet([a, a])
    assert raised.value.code == "e.input.multi.compartment-duplicate.f"


def test_present_only_skips_absent_and_unmeasured():
    cs = CompartmentSet([
        Compartment(name="public", status="present"),
        Compartment(name="orchestrator", status="absent"),
        Compartment(name="operation-log", status="not-measured"),
    ])
    assert [c.name for c in cs.present()] == ["public"]
    assert cs.subset(["public", "orchestrator"]).names() == ["public", "orchestrator"]


def test_subset_naming_a_compartment_the_set_lacks_is_refused():
    cs = CompartmentSet([Compartment(name="public", status="present")])
    with pytest.raises(BakoboError) as raised:
        cs.subset(["verifier:v9"])
    assert raised.value.code == "e.state.missing.compartment.f"


def test_ground_truth_resolves_nodes_to_citizens():
    gt = GroundTruth(
        citizen_rows=[5, 9],
        presentations={"p1": 0, "p2": 1},
        identities={"r1": 1},
        artifacts={"Esaid": 0},
        domains={"p1": "alcohol", "p2": "pharmacy"},
    )
    assert gt.citizen_of("p:p1") == 0
    assert gt.citizen_of("id:r1") == 1
    assert gt.citizen_of("x:Esaid") == 0
    assert gt.citizen_of("x:unknown") is None
    assert gt.citizen_of("p:nope") is None
    with pytest.raises(BakoboError) as raised:
        gt.citizen_of("q:p1")
    assert raised.value.code == "e.input.format.node.f"


def test_run_directory_round_trip_keeps_bytes_and_keeps_ground_truth_apart(tmp_path):
    cs = CompartmentSet([
        Compartment(name="public", status="present",
                    streams={"kel:Eiss": b"-KERI\x00bytes", "tel:Ereg": b"tel"}),
        Compartment(name="verifier:v1", status="present", presentations=[_presentation()],
                    logs=[LogLine(3.25, "203.0.113.9", "GET /tel/Ereg")]),
        Compartment(name="issuing-home:h0", status="present",
                    records={"pool": [{"registry": "Ereg", "said": "Esaid", "holder": "Ehold"}]}),
        Compartment(name="orchestrator", status="absent"),
        Compartment(name="operation-log", status="not-measured", note="no export"),
    ])
    gt = GroundTruth(citizen_rows=[5], presentations={"p1": 0}, identities={},
                     artifacts={"Esaid": 0}, domains={"p1": "alcohol"})
    rundir.write_compartments(tmp_path, cs)
    rundir.write_ground_truth(tmp_path, gt)
    back = rundir.read_compartments(tmp_path)
    assert back == cs
    assert rundir.read_ground_truth(tmp_path) == gt
    # Nothing under compartments/ mentions the ground truth file or a citizen row.
    for path in (tmp_path / "compartments").rglob("*"):
        if path.is_file():
            assert b"citizen" not in path.read_bytes()


def test_reading_a_run_directory_without_compartments_is_refused(tmp_path):
    with pytest.raises(BakoboError) as raised:
        rundir.read_compartments(tmp_path)
    assert raised.value.code == "e.state.missing.run-compartments.f"


def test_knowledge_round_trips(tmp_path):
    k = Knowledge(copies=3, per_citizen=3, issuance_block=3, issuers={"Eiss": "0"},
                  verifier_addresses={"198.51.100.10": "v1"}, service_addresses=["10.9.0.1"])
    rundir.write_knowledge(tmp_path, k)
    assert rundir.read_knowledge(tmp_path) == k


def test_a_time_that_is_not_finite_is_refused():
    with pytest.raises(BakoboError) as raised:
        Compartment(name="public", status="present",
                    logs=[LogLine(float("nan"), "10.0.0.1", "x")])
    assert raised.value.code == "e.input.range.compartment-time.f"
    with pytest.raises(BakoboError):
        Compartment(name="verifier:v1", status="present",
                    presentations=[dataclasses.replace(_presentation(), time=float("inf"))])
    with pytest.raises(BakoboError) as raised:
        Compartment(name="public", status="present", logs=[LogLine("bad", "10.0.0.1", "x")])
    assert raised.value.code == "e.input.range.compartment-time.f"
