"""Attacks on hand-built and edge-case inputs: isolation (Part B item 2), the log scan's plants
(item 10), and what each attack does when its material is partial."""

import dataclasses
import json
import random

from worlds import world

from keri_priv_analysis import rundir
from keri_priv_analysis.attacks import ATTACKS, CATALOGUE, dedupe
from keri_priv_analysis.attacks.common import read_record
from keri_priv_analysis.attacks.protocol import kel_anchor_adjacency, registry_inception_adjacency
from keri_priv_analysis.model import (
    Compartment,
    CompartmentSet,
    Join,
    Knowledge,
    LogLine,
    Presentation,
)

ID = [f"E{c * 43}" for c in "ABCDEFGH"]  # eight distinct identifiers, 44 characters each
KNOW = Knowledge(copies=2, per_citizen=2, issuance_block=2, issuers={}, verifier_addresses={},
                 service_addresses=[])


def test_attacks_never_see_ground_truth(tmp_path):
    _s, _population, cs, truth, k = world(count=8, copies=4, log_join_material=True,
                                        status_updates="lockstep")
    rundir.write_compartments(tmp_path, cs)
    rundir.write_ground_truth(tmp_path, truth)
    before = {a.name: sorted(map(repr, a.run(rundir.read_compartments(tmp_path), k)))
              for a in CATALOGUE}
    shuffled = list(truth.presentations.items())
    citizens = [c for _, c in shuffled]
    random.Random(5).shuffle(citizens)
    permuted = dataclasses.replace(
        truth, presentations={h: c for (h, _), c in zip(shuffled, citizens, strict=True)},
        citizen_rows=list(reversed(truth.citizen_rows)))
    rundir.write_ground_truth(tmp_path, permuted)
    after = {a.name: sorted(map(repr, a.run(rundir.read_compartments(tmp_path), k)))
             for a in CATALOGUE}
    assert before == after


def _log_set(*lines):
    return CompartmentSet([Compartment(
        name="issuing-home:0", status="present",
        logs=[LogLine(float(n), "10.0.0.1", text) for n, text in enumerate(lines)])])


def test_log_scan_finds_every_plant_in_every_known_format():
    plain = f"bulk issuance for {ID[0]}: registry {ID[1]} credential {ID[2]}"
    as_json = json.dumps({"event": "issued", "registry": ID[3], "holder": ID[4]})
    key_value = f"level=info said={ID[5]} management={ID[6]}"
    joins = ATTACKS["log-scan"].run(_log_set(plain, as_json, key_value, f"published {ID[7]}"),
                                    KNOW)
    pairs = {frozenset((j.a, j.b)) for j in joins}
    assert pairs == {frozenset((f"x:{ID[0]}", f"x:{ID[1]}")),
                     frozenset((f"x:{ID[1]}", f"x:{ID[2]}")),
                     frozenset((f"x:{ID[3]}", f"x:{ID[4]}")),
                     frozenset((f"x:{ID[5]}", f"x:{ID[6]}"))}


def test_log_scan_joins_nothing_in_logs_without_plants():
    lines = [f"provisioned registry {i}" for i in ID] + [f"published {ID[0]} twice {ID[0]}"]
    assert ATTACKS["log-scan"].run(_log_set(*lines), KNOW) == []


def test_log_scan_ties_planted_identifiers_to_presentations_and_identities():
    _s, _population, cs, _truth, k = world(count=6, copies=4, log_join_material=True)
    joins = ATTACKS["log-scan"].run(cs, k)
    assert any(j.a.startswith("p:") for j in joins)
    assert any(j.a.startswith("id:") for j in joins)


def test_an_attack_says_which_compartments_it_lacks():
    cs = CompartmentSet([Compartment(name="public", status="present"),
                         Compartment(name="verifier:v", status="not-measured")])
    assert ATTACKS["shared-registry"].missing(cs) == ["verifier"]
    assert ATTACKS["holder-infrastructure"].missing(cs) == [
        "access-log:mailbox or access-log:holder-witness", "verifier"]
    assert ATTACKS["log-scan"].missing(cs) == []


def test_dedupe_keeps_one_join_per_pair_at_its_highest_confidence():
    joins = [Join("p:a", "p:b", 0.4, "t"), Join("p:b", "p:a", 0.9, "t"), Join("p:a", "p:c", 1, "t"),
             Join("p:c", "p:a", 0.5, "t")]
    assert sorted((j.a, j.b, j.confidence) for j in dedupe(joins)) == [
        ("p:a", "p:c", 1), ("p:b", "p:a", 0.9)]


def test_the_public_record_ignores_streams_it_does_not_read_and_unknown_registries():
    _s, _population, cs, _truth, _k = world(count=6, copies=4)
    streams = dict(cs["public"].streams) | {"note:readme": b"not cesr"}
    record = read_record(CompartmentSet([Compartment(name="public", status="present",
                                                     streams=streams)]))
    p = cs.presentations()[0]
    assert record.issuance(dataclasses.replace(p, registry="E" + "Z" * 43)) is None
    only_rip = {**record.tels, p.registry: record.tels[p.registry][:1]}
    assert dataclasses.replace(record, tels=only_rip).issuance(
        dataclasses.replace(p, said="E" + "Q" * 43)) is None


def test_adjacency_skips_presentations_whose_anchor_is_unknown_or_outside_a_run():
    _s, _population, cs, _truth, k = world(count=6, copies=4)
    held = cs["verifier:pharmacy"].presentations
    tel = read_record(cs).tels[held[0].registry]
    strays = [dataclasses.replace(held[0], handle="stray1", registry="E" + "Z" * 43),
              dataclasses.replace(held[1], handle="stray2", registry=tel[1]["d"])]
    odd = CompartmentSet([*(c for c in cs if c.name != "verifier:pharmacy"),
                          dataclasses.replace(cs["verifier:pharmacy"],
                                              presentations=held + strays)])
    for attack in (kel_anchor_adjacency, registry_inception_adjacency):
        nodes = {n for j in attack(odd, k) for n in (j.a, j.b)}
        assert "p:stray1" not in nodes


def test_custodial_join_tolerates_rows_without_the_fields_it_wants():
    cs = CompartmentSet([
        Compartment(name="issuing-home:0", status="present", records={"pool": [
            {"registry": ID[0], "state": "issued"},
            {"holder": ID[1], "management": ID[2]},
            {"holder": ID[3], "management": ID[4]}]}),
        Compartment(name="identity-proofing", status="present", records={"iar": [
            {"record": "iar-1"}, {"record": "iar-2", "management": ID[2]}]}),
        Compartment(name="verifier:v", status="present", presentations=[
            Presentation(handle="h", verifier="v", time=0.0, domain="d", disclosed={},
                         said=ID[5], registry=ID[6], issuer=ID[7], holder=ID[3], raw=b"")]),
    ])
    joins = ATTACKS["custodial-join"].run(cs, KNOW)
    # The presentation's holder maps to a management AID nobody's identity record carries, so it
    # is linked to nothing; only the row whose management AID is on file joins an identity.
    assert [(j.a, j.b) for j in joins] == [(f"x:{ID[1]}", "id:iar-2")]


def test_stolen_home_identity_joins_presentations_without_identity_proofing():
    cs = CompartmentSet([
        Compartment(name="issuing-home:0", status="present", records={
            "pool": [{"said": ID[0], "holder": ID[1], "management": ID[2]}],
            "identities": [{"record": "core-1", "management": ID[2],
                            "givenName": "Ada", "familyName": "Lovelace"}]}),
        Compartment(name="verifier:v", status="present", presentations=[
            Presentation(handle="h", verifier="v", time=0.0, domain="d", disclosed={},
                         said=ID[0], registry=ID[3], issuer=ID[4], holder=ID[1], raw=b"")]),
    ])
    joins = ATTACKS["custodial-join"].run(cs, KNOW)
    assert ("p:h", "id:core-1") in {(j.a, j.b) for j in joins}


def test_an_unrelated_record_cannot_replace_a_known_identity_join():
    # Two present compartments carry identity records for one management AID. Neither may erase
    # the other: an attacker holding both rows can follow either, so both joins are made.
    cs = CompartmentSet([
        Compartment(name="issuing-home:0", status="present", records={
            "pool": [{"said": ID[0], "holder": ID[1], "management": ID[2]}],
            "identities": [{"record": "core-1", "management": ID[2]}]}),
        Compartment(name="operation-log", status="present", records={
            "identities": [{"record": "unrelated", "management": ID[2]}]}),
        Compartment(name="verifier:v", status="present", presentations=[
            Presentation(handle="h", verifier="v", time=0.0, domain="d", disclosed={},
                         said=ID[0], registry=ID[3], issuer=ID[4], holder=ID[1], raw=b"")]),
    ])
    pairs = {(j.a, j.b) for j in ATTACKS["custodial-join"].run(cs, KNOW)}
    assert {("p:h", "id:core-1"), ("p:h", "id:unrelated")} <= pairs
    assert {(f"x:{ID[0]}", "id:core-1"), (f"x:{ID[0]}", "id:unrelated")} <= pairs


def test_log_scan_joins_every_identity_record_that_carries_a_logged_key():
    cs = CompartmentSet([
        Compartment(name="identity-proofing", status="present", records={"iar": [
            {"record": "iar-1", "management": ID[2]},
            {"record": "iar-2", "management": ID[2]}]}),
        Compartment(name="access-log:x", status="present",
                    logs=[LogLine(0.0, "s", f"{ID[2]} {ID[3]}")]),
    ])
    pairs = {(j.a, j.b) for j in ATTACKS["log-scan"].run(cs, KNOW)}
    assert {("id:iar-1", f"x:{ID[2]}"), ("id:iar-2", f"x:{ID[2]}")} <= pairs


def test_a_v1_credential_is_found_by_name_and_a_blinded_one_by_position():
    from keri_priv_analysis.attacks.common import Record
    record = Record(tels={"R": [
        {"kind": "inception", "registry": "R", "credential": None, "d": "E0", "dt": None},
        {"kind": "update", "registry": "R", "credential": "C1", "d": "E1", "dt": None},
        {"kind": "update", "registry": "R", "credential": "C2", "d": "E2", "dt": None}]},
        seals={}, kels={}, batches=[])
    p = Presentation(handle="h", verifier="v", time=0.0, domain="d", disclosed={}, said="C2",
                     registry="R", issuer="I", holder="H", raw=b"")
    assert record.issuance(p)["d"] == "E2"
    assert record.issuance(dataclasses.replace(p, said="C9"))["d"] == "E1"


def test_holder_kel_links_per_citizen_witness_sets_with_high_but_uncertain_confidence():
    _s, _population, cs, truth, k = world(count=20, copies=4, holder_witnesses="per-citizen")
    joins = dedupe(ATTACKS["holder-kel"].run(cs, k))
    assert joins and all(0.8 < j.confidence < 1.0 for j in joins)
    right = sum(truth.citizen_of(j.a) == truth.citizen_of(j.b) for j in joins)
    assert right / len(joins) > 0.9


def test_holder_kel_finds_nothing_without_transferable_holder_aids():
    _s, _population, cs, _truth, _k = world(count=6, copies=4, holder_aids="nontransferable")
    assert ATTACKS["holder-kel"].missing(cs) == ["holder-AID KELs in a verifier's compartment"]


def test_payload_invariance_links_copies_sharing_an_edge():
    _s, _population, cs, truth, k = world(count=6, copies=4, copy_template="shared-edge")
    joins = ATTACKS["payload-invariance"].run(cs, k)
    assert joins and all(truth.citizen_of(j.a) == truth.citizen_of(j.b) for j in joins)


def test_an_attack_whose_material_is_absent_is_not_measured_rather_than_clean():
    _s, _population, cs, _truth, _k = world(count=6, copies=4)
    assert ATTACKS["shared-batch-root"].missing(cs) == ["Registrar batches in the public record"]
    assert ATTACKS["verifier-probing"].missing(cs) == ["a verifier's own probe log"]
    assert ATTACKS["hosted-agent"].missing(cs) == ["access-log:hosted-agent"]
    lacking = CompartmentSet([*cs, Compartment(name="access-log:hosted-agent", status="present")]
                             if "access-log:hosted-agent" not in cs else
                             [c if c.name != "access-log:hosted-agent" else
                              Compartment(name=c.name, status="present") for c in cs])
    assert ATTACKS["hosted-agent"].missing(lacking) == ["log lines in access-log:hosted-agent"]


def test_log_scan_follows_a_trace_id_across_lines():
    lines = [f"[trace=0a1b2c3d4e] bulk issuance for {ID[0]}",
             f"[trace=0a1b2c3d4e] issued credential {ID[1]}",
             f"request_id: 9f8e7d6c5b issued credential {ID[2]}",
             f"request_id: 9f8e7d6c5b holder {ID[3]}",
             f"[trace=ffffffffff] issued credential {ID[4]}"]
    pairs = {frozenset((j.a, j.b)) for j in ATTACKS["log-scan"].run(_log_set(*lines), KNOW)}
    assert pairs == {frozenset((f"x:{ID[0]}", f"x:{ID[1]}")),
                     frozenset((f"x:{ID[2]}", f"x:{ID[3]}"))}


def test_payload_values_read_expanded_sections_and_skip_what_is_not_a_credential():
    from keri_priv_analysis.attacks.held import _first_acdc, _payload_values
    acdc = {"a": {"d": "Ea", "u": "0Au", "name": "x"}, "e": {"d": "Ee", "core": {"n": "En"}},
            "r": "Er"}
    assert _payload_values(acdc) == [("a.d", "Ea"), ("a.u", "0Au"), ("e.d", "Ee"),
                                     ("e.core.n", "En"), ("r", "Er")]
    assert _payload_values({"a": {"name": "x"}}) == []
    _s, _population, cs, _truth, k = world(count=6, copies=4)
    tel_only = cs.presentations()[0].raw.split(b'{"v":"ACDC', 2)
    assert _first_acdc(b'{"v":"ACDC' + tel_only[2]) is None  # the TEL alone: rip and upd
    blank = CompartmentSet([dataclasses.replace(
        cs["verifier:pharmacy"], presentations=[dataclasses.replace(
            cs.presentations()[0], raw=b'{"v":"ACDC' + tel_only[2])])])
    assert ATTACKS["payload-invariance"].run(blank, k) == []


def test_holder_kel_skips_streams_and_inceptions_it_cannot_use():
    _s, _population, cs, _truth, k = world(count=6, copies=4, holder_aids="delegated")
    verifier = cs["verifier:pharmacy"]
    odd = CompartmentSet([dataclasses.replace(
        verifier, streams={"note:x": b"", **dict(list(verifier.streams.items())[:1])})])
    # One holder KEL and a stream that is not a KEL: nothing to compare witness sets against.
    joins = ATTACKS["holder-kel"].run(odd, k)
    assert joins == []
    _name, kel = next(iter(verifier.streams.items()))
    stranger = CompartmentSet([dataclasses.replace(verifier, streams={"kel:E" + "Q" * 43: kel})])
    assert ATTACKS["holder-kel"].run(stranger, k) == []  # no inception of the named AID


def test_holder_kel_ignores_an_inception_without_witnesses():
    from keri_priv_analysis.generator import _World
    s, population, cs, _truth, k = world(count=6, copies=4)
    w = _World(s, population)
    _, serder, kel = w._transferable(witnesses=())
    verifier = dataclasses.replace(cs["verifier:pharmacy"], streams={f"kel:{serder.pre}": kel})
    assert ATTACKS["holder-kel"].run(CompartmentSet([verifier]), k) == []


def test_status_updates_to_one_credential_do_not_dilute_a_shared_registry_join():
    from keri_priv_analysis.attacks.common import Record
    from keri_priv_analysis.attacks.protocol import _credentials_in
    updates = [{"kind": "update", "registry": "R", "credential": c, "d": f"E{n}", "dt": None}
               for n, c in enumerate(["C1", "C2"] + ["C1"] * 100)]
    record = Record(tels={"R": updates}, seals={}, kels={}, batches=[])
    assert _credentials_in(record, "R") == 2
    blinded = [dict(u, credential=None) for u in updates[:3]]
    assert _credentials_in(Record(tels={"R": blinded}, seals={}, kels={}, batches=[]), "R") == 3


def test_sessions_split_at_the_widest_gaps_whatever_the_spacing_inside_them():
    from keri_priv_analysis.attacks.common import sessions
    # Three sessions of three, with seconds between a session's events and hours between sessions.
    times = {f"{s}{i}": s * 7200.0 + i * 3.0 for s in range(3) for i in range(3)}
    groups = sessions(times, 3)
    assert sorted(sorted(g) for g in groups.values()) == [
        ["00", "01", "02"], ["10", "11", "12"], ["20", "21", "22"]]
    assert sessions({"a": 1.0, "b": float("nan"), "c": 2.0}, 2) == {0: ["a", "c"]}
    assert sessions({}, 3) == {}


def test_log_scan_ignores_the_states_public_infrastructure():
    witness = ID[7]
    lines = [f"GET /oobi/{ID[0]}/witness/{witness}", f"GET /oobi/{ID[1]}/witness/{witness}"]
    public = dataclasses.replace(KNOW, infrastructure=[witness])
    assert ATTACKS["log-scan"].run(_log_set(*lines), public) == []
    assert ATTACKS["log-scan"].run(_log_set(*lines), KNOW) != []


def test_a_malformed_batch_is_refused_with_a_code():
    from bakobo.errors import BakoboError

    from keri_priv_analysis.attacks.common import _batch
    for data in (b"[]", b"not json", b'{"registries": [1]}', b"{}"):
        try:
            _batch("batch:0", data)
        except BakoboError as exc:
            assert exc.code == "e.input.format.stream-shape.f"
        else:
            raise AssertionError(data)
    assert _batch("batch:0", b'{"registries": ["Ea"]}') == ["Ea"]


def test_hosted_agent_reads_any_log_format_by_its_identifiers():
    _s, _population, cs, _truth, k = world(count=6, copies=4, hosted_agents="per-citizen")
    held = cs.presentations()
    agent = ID[6]
    lines = [f"GET /oobi/{held[0].holder}/agent/{agent}",
             f"GET /oobi/{held[1].holder}/agent/{agent}"]
    logs = CompartmentSet([*(c for c in cs if c.name != "access-log:hosted-agent"),
                           Compartment(name="access-log:hosted-agent", status="present",
                                       logs=[LogLine(1.0, "10.0.0.9", t) for t in lines])])
    pairs = {frozenset((j.a, j.b)) for j in ATTACKS["hosted-agent"].run(logs, k)}
    assert frozenset((f"p:{held[0].handle}", f"p:{held[1].handle}")) in pairs


def test_agent_end_role_needs_end_role_records():
    _s, _population, cs, _truth, k = world(count=6, copies=4)
    assert ATTACKS["agent-end-role"].missing(cs) == [
        "end-role records in a verifier's compartment"]
    held = cs["verifier:pharmacy"].presentations
    rows = [{"aid": held[0].holder, "role": "controller", "eid": ID[0]},
            {"aid": held[1].holder, "role": "agent", "eid": ID[0]}]
    odd = CompartmentSet([dataclasses.replace(cs["verifier:pharmacy"],
                                              records={"end-roles": rows})])
    assert ATTACKS["agent-end-role"].run(odd, k) == []  # a controller role names no agent


def test_agent_end_role_never_joins_through_a_shared_agent():
    _s, _population, cs, _truth, k = world(count=6, copies=4)
    held = cs["verifier:pharmacy"].presentations
    rows = [{"aid": held[0].holder, "role": "agent", "eid": ID[0]},
            {"aid": held[1].holder, "role": "agent", "eid": ID[0]}]
    shared = CompartmentSet([dataclasses.replace(cs["verifier:pharmacy"],
                                                 records={"end-roles": rows})])
    assert ATTACKS["agent-end-role"].run(shared, k) != []
    public = dataclasses.replace(k, infrastructure=[*k.infrastructure, ID[0]])
    assert ATTACKS["agent-end-role"].run(shared, public) == []  # the State's agent serves many


def test_verifier_probing_reads_only_probe_lines_and_hosted_agent_ignores_infrastructure():
    _s, _population, cs, _truth, k = world(count=6, copies=4)
    held = cs["verifier:pharmacy"].presentations
    ordinary = [LogLine(1.0, "198.51.100.10", f"admitted grant for {p.registry}") for p in held]
    plain = CompartmentSet([dataclasses.replace(cs["verifier:pharmacy"], logs=ordinary)])
    assert ATTACKS["verifier-probing"].missing(plain) == ["a verifier's own probe log"]
    issuer = held[0].issuer
    lines = [f"wallet {issuer} sends {p.holder}" for p in held[:2]]
    agents = CompartmentSet([cs["verifier:pharmacy"], Compartment(
        name="access-log:hosted-agent", status="present",
        logs=[LogLine(1.0, "10.0.0.9", t) for t in lines])])
    public = dataclasses.replace(k, infrastructure=[*k.infrastructure, issuer])
    joined = ATTACKS["hosted-agent"].run(agents, public)
    # With the issuer known as infrastructure the lines fall back to their text, which is the
    # same for both, so they still group: by the text, never by the issuer's AID.
    assert all("x:" not in j.a for j in joined)


def test_verifier_probing_skips_ordinary_lines_beside_its_probe_lines():
    _s, _population, cs, _truth, k = world(count=6, copies=4, verifier_probing=True)
    v = cs["verifier:pharmacy"]
    noisy = CompartmentSet([*(c for c in cs if c.name != v.name), dataclasses.replace(
        v, logs=[*v.logs, LogLine(2.0, "198.51.100.11", f"admitted {v.presentations[0].said}")])])
    assert ATTACKS["verifier-probing"].run(noisy, k) == ATTACKS["verifier-probing"].run(cs, k)


def test_payload_invariance_ignores_values_everyone_carries():
    from keri_priv_analysis.attacks.held import _first_acdc
    _s, _population, cs, _truth, k = world(count=6, copies=4, copy_template="shared-edge")
    edges = [_first_acdc(p.raw)["e"] for p in cs.presentations()]
    public = dataclasses.replace(k, infrastructure=[*k.infrastructure, *edges])
    assert ATTACKS["payload-invariance"].run(cs, public) == []
