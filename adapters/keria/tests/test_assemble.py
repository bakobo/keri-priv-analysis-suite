from datetime import UTC, datetime

from kpa_adapter_keria import plan as planning
from kpa_adapter_keria.assemble import ABSENT, assemble
from kpa_adapter_keria.clock import PROVISIONING


def ident(c):
    return "E" + c * 43


ISSUER, REGISTRY, VERIFIER, WALLET_AGENT = ident("i"), ident("r"), ident("v"), ident("w")
HOLDERS = [[ident("a"), ident("b")], [ident("c"), ident("d")]]
SAIDS = [[ident("s"), ident("t")], [ident("u"), ident("x")]]
WALL = 1_800_000_000.0


def export_for(p):
    creds = [{"citizen": i.citizen, "copy": i.copy, "said": SAIDS[i.citizen][i.copy],
              "registry": REGISTRY, "issuer": ISSUER, "holder": HOLDERS[i.citizen][i.copy],
              "home": 0} for i in p.issuance]
    shown = [{**creds[[(c["citizen"], c["copy"]) for c in creds].index((s.citizen, s.copy))],
              "verifier": s.verifier, "grant": ident("g"), "raw": f"raw-{n}"}
             for n, s in enumerate(p.showings)]
    timeline = [["provision", -1, WALL]]
    timeline += [["issue", n, WALL + 10 + n] for n in range(len(p.issuance))]
    timeline += [["present", n, WALL + 100 + n] for n in range(len(p.showings))]
    stamp = datetime.fromtimestamp(WALL + 100.5, tz=UTC).isoformat()
    verifier = {"aid": VERIFIER, "agent": ident("y"), "controller": ident("z"),
                "kels": {HOLDERS[0][0]: "kel-bytes"},
                "records": {"exchanges": [{"said": ident("g"), "dt": stamp}],
                            "end-roles": [{"aid": HOLDERS[0][0], "role": "agent",
                                           "eid": WALLET_AGENT}]},
                "logs": [[WALL + 100, "2026 line naming " + HOLDERS[0][0]]],
                "address": "127.0.0.1:2"}
    return {
        "issuers": [{"aid": ISSUER, "registry": REGISTRY, "agent": ident("j"),
                     "controller": ident("k")}],
        "verifiers": {"liquor-store": verifier,
                      "pharmacy": {**verifier, "address": "127.0.0.1:3", "kels": {}}},
        "citizens": [], "credentials": creds, "presentations": shown,
        "public": {f"kel:{ISSUER}": "kel", f"tel:{REGISTRY}": "tel"},
        "homes": [{"records": {"credentials": [{"said": SAIDS[0][0], "management": WALLET_AGENT,
                                                "dt": "ignored"}],
                               "end-roles": [{"aid": HOLDERS[0][0], "role": "agent",
                                              "eid": WALLET_AGENT}]},
                   "logs": [[WALL, "provisioning"], [WALL + 10, "issuing"]],
                   "address": "127.0.0.1:1"}],
        "wallet": {"records": {"agents": [{"agent": WALLET_AGENT, "holder": HOLDERS[0][0]}]},
                   "logs": [[WALL + 11, "wallet line"]], "address": "127.0.0.1:4"},
        "timeline": timeline,
        "artifacts": {HOLDERS[0][0]: 0, SAIDS[0][0]: 0},
        "nobody": [ISSUER, REGISTRY],
    }


def test_compartments_are_every_name_the_scenario_has(scenario, population):
    p = planning.build(scenario, population)
    cs, _, _ = assemble(scenario, p, export_for(p), population)
    assert set(cs.names()) == scenario.compartment_names()
    for name, note in ABSENT.items():
        assert cs[name].status == "absent" and cs[name].note == note
    assert cs["access-log:hosted-agent"].status == "present"


def test_presentations_disclose_the_whole_credential_at_scenario_times(scenario, population):
    p = planning.build(scenario, population)
    cs, truth, _ = assemble(scenario, p, export_for(p), population)
    held = cs.presentations()
    assert len(held) == 4
    for s in p.showings:
        got = next(x for x in held if x.handle == s.handle)
        row = population.row(p.rows[s.citizen])
        assert got.time == s.time and got.domain == s.domain and got.verifier == s.verifier
        assert got.disclosed == {"age-band": row["age-band"], "county": row["county"]}
        assert got.said == SAIDS[s.citizen][s.copy] and got.holder == HOLDERS[s.citizen][s.copy]
        assert got.raw.startswith(b"raw-")
        assert truth.presentations[s.handle] == s.citizen and truth.domains[s.handle] == s.domain
    assert cs["verifier:liquor-store"].streams == {f"kel:{HOLDERS[0][0]}": b"kel-bytes"}


def test_records_and_logs_move_onto_the_scenario_clock(scenario, population):
    p = planning.build(scenario, population)
    cs, _, _ = assemble(scenario, p, export_for(p), population)
    home = cs["issuing-home:0"]
    first = next(i for i in p.issuance if (i.citizen, i.copy) == (0, 0))
    assert home.records["credentials"][0]["time"] == repr(first.time)
    assert "time" not in home.records["end-roles"][0]
    assert [line.time for line in home.logs] == [PROVISIONING, p.issuance[0].time]
    assert {line.source for line in home.logs} == {"127.0.0.1:1"}
    verifier = cs["verifier:liquor-store"]
    assert verifier.records["exchanges"][0]["time"] == repr(p.showings[0].time)
    assert verifier.logs[0].time == p.showings[0].time
    wallet = cs["access-log:hosted-agent"]
    assert wallet.logs[0].time == p.issuance[1].time and "time" not in wallet.records["agents"][0]


def test_truth_and_knowledge(scenario, population):
    p = planning.build(scenario, population)
    _, truth, knowledge = assemble(scenario, p, export_for(p), population)
    assert truth.citizen_rows == p.rows and truth.identities == {}
    assert truth.artifacts == {HOLDERS[0][0]: 0, SAIDS[0][0]: 0}
    assert truth.decoys == [] and knowledge.infrastructure == [ISSUER, REGISTRY]
    assert knowledge.copies == knowledge.per_citizen == knowledge.issuance_block == 2
    assert knowledge.issuers == {ISSUER: "0"}
    assert knowledge.verifier_addresses == {"127.0.0.1:2": "liquor-store",
                                            "127.0.0.1:3": "pharmacy"}
    assert knowledge.service_addresses == ["127.0.0.1:1", "127.0.0.1:4"]
