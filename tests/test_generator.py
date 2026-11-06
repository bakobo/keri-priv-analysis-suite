"""The synthetic generator: its bytes are real, its worlds are deterministic, and each setting does
what the countermeasure it models says."""

import pytest
from worlds import scenario, world

from keri_priv_analysis import cesr, contract, rundir
from keri_priv_analysis.attacks import CATALOGUE
from keri_priv_analysis.generator import PROVISIONING, Generator, stamp


def test_every_attack_has_a_generator_cause():
    assert set(Generator().causes(scenario())) == {attack.name for attack in CATALOGUE}


def _issuance_stamps(cs):
    out = []
    for name, data in cs["public"].streams.items():
        if name.startswith("tel:"):
            out += [e["dt"] for e in cesr.messages(data) if e["t"] in ("upd", "bup")]
    return out


def test_stamps_are_rfc3339_and_truncate_to_the_granularity():
    assert stamp(0.0, 0) == "2026-11-01T00:00:00.000000+00:00"
    assert stamp(90061.123456, 0) == "2026-11-02T01:01:01.123456+00:00"
    assert stamp(90061.123456, 86400) == "2026-11-02T00:00:00.000000+00:00"
    assert stamp(PROVISIONING, 0) == "2026-10-31T00:00:00.000000+00:00"


SETTINGS = [
    {},
    {"registry_scope": "citizen", "registry_allocation": "random"},
    {"registry_scope": "issuer", "issuance_order": "mixed"},
    {"tel_updates": "bup", "status_updates": "lockstep", "dt_granularity": 86400.0},
    {"status_updates": "independent", "decoys": 7, "batch_size": 5, "batch_mix": "mixed"},
    {"batch_size": 6, "batch_mix": "citizen", "publication_window": 3600.0,
     "verifier_probing": True},
    {"holder_network": "mixed", "holder_status_reads": True, "hosted_agents": "per-citizen"},
    {"hosted_agents": "shared", "identity_oracle": True, "log_join_material": True},
    {"sealed_revocation_map": True, "decoys": 3},
    {"holder_aids": "delegated", "holder_witnesses": "per-citizen", "copy_template": "shared-edge",
     "first_seen": "constant", "anchor_order": "per-citizen"},
    {"holder_aids": "nontransferable", "copy_template": "cloned-attributes",
     "anchor_order": "batched", "batch_size": 4, "batch_mix": "ordered"},
    {"anchor_order": "shuffled", "decoys": 2},
]


@pytest.mark.parametrize("settings", SETTINGS, ids=lambda s: ",".join(s) or "baseline")
def test_the_generator_passes_the_adapter_contract(settings):
    s, population, cs, truth, knowledge = world(count=12, copies=4, **settings)
    assert contract.check(s, cs, truth, knowledge, population) == []


def test_the_same_seed_gives_byte_identical_compartments(tmp_path):
    a = world(count=8, copies=3, seed=11)[2]
    from worlds import _world, scenario  # a second, uncached build of the same world

    from keri_priv_analysis.generator import Generator
    s = scenario(count=8, copies=3, seed=11)
    b = Generator().run(s, world(count=8, copies=3, seed=11)[1])[0]
    rundir.write_compartments(tmp_path / "a", a)
    rundir.write_compartments(tmp_path / "b", b)
    for path in (tmp_path / "a").rglob("*"):
        if path.is_file():
            assert path.read_bytes() == (tmp_path / "b" / path.relative_to(tmp_path / "a")
                                         ).read_bytes(), path
    assert _world.cache_info().currsize >= 1


def test_microsecond_stamps_by_default_and_day_stamps_when_coarse():
    fine = _issuance_stamps(world(count=6, copies=3)[2])
    assert any(not s.endswith("00:00:00.000000+00:00") for s in fine)
    coarse = _issuance_stamps(world(count=6, copies=3, dt_granularity=86400.0)[2])
    assert all(s.endswith("T00:00:00.000000+00:00") for s in coarse)


def test_per_citizen_issuance_keeps_a_citizens_copies_together_and_mixed_does_not():
    def runs(cs, truth):
        order = []
        for name, data in cs["public"].streams.items():
            if name.startswith("kel:"):
                for event in cesr.messages(data):
                    for seal in event.get("a", []):
                        if seal.get("s") != "0":  # issuance, not inception
                            order.append((event["s"], truth.artifacts.get(seal["i"])))
        return order
    _, _, cs, truth, _ = world(count=10, copies=4, homes=1)
    citizens = [c for _, c in sorted(runs(cs, truth), key=lambda x: int(x[0], 16))]
    assert all(len(set(citizens[i:i + 4])) == 1 for i in range(0, len(citizens), 4))
    _s, _, cs, truth, _ = world(count=10, copies=4, homes=1, issuance_order="mixed")
    citizens = [c for _, c in sorted(runs(cs, truth), key=lambda x: int(x[0], 16))]
    assert not all(len(set(citizens[i:i + 4])) == 1 for i in range(0, len(citizens), 4))


def test_registry_scope_sets_how_many_credentials_share_a_registry():
    def per_registry(cs):
        return sorted(len([e for e in cesr.messages(d) if e["t"] != "rip"])
                      for n, d in cs["public"].streams.items() if n.startswith("tel:"))
    assert set(per_registry(world(count=6, copies=3, homes=1)[2])) == {1}
    assert set(per_registry(world(count=6, copies=3, homes=1, registry_scope="citizen")[2])) == {3}
    assert per_registry(world(count=6, copies=3, homes=1, registry_scope="issuer")[2]) == [18]


def test_sealed_revocation_map_and_identity_oracle_change_what_the_stores_hold():
    plain = world(count=6, copies=3)[2]
    sealed = world(count=6, copies=3, sealed_revocation_map=True)[2]
    oracle = world(count=6, copies=3, identity_oracle=True)[2]
    row = plain["issuing-home:0"].records["pool"][0]
    assert "management" in row
    assert "management" not in sealed["issuing-home:0"].records["pool"][0]
    assert set(sealed["revocation-authority"].records["revocation"][0]) == {"sealed"}
    home_keys = {r["management"] for c in oracle.of_kind("issuing-home")
                 for r in c.records["pool"]}
    idp_keys = {r["management"] for r in oracle["identity-proofing"].records["iar"]}
    assert not home_keys & idp_keys
    plain_home = {r["management"] for c in plain.of_kind("issuing-home")
                  for r in c.records["pool"]}
    assert plain_home <= {r["management"] for r in plain["identity-proofing"].records["iar"]}


def test_generator_models_named_core_records_retained_by_a_home():
    _, _, plain, truth, knowledge = world(count=6, copies=3, homes=1)
    home = plain["issuing-home:0"]
    identities = home.records["identities"]
    assert len(identities) == 18
    assert all(truth.identities[row["record"]] == truth.artifacts[row["management"]]
               for row in identities)
    from keri_priv_analysis.attacks.custodial import custodial_join
    from keri_priv_analysis.model import CompartmentSet
    view = CompartmentSet([home, plain["verifier:liquor-store"]])
    assert any(join.b.startswith("id:") for join in custodial_join(view, knowledge))
    sealed = world(count=6, copies=3, homes=1, sealed_revocation_map=True)
    sealed_home = sealed[2]["issuing-home:0"]
    assert sealed_home.records["identities"]
    sealed_view = CompartmentSet([sealed_home, sealed[2]["verifier:liquor-store"]])
    assert any(join.b.startswith("id:") for join in custodial_join(sealed_view, sealed[4]))
    assert all(not c.records["identities"] for c in world(
        count=6, copies=3, homes=1, identity_oracle=True)[2].of_kind("issuing-home"))


def test_what_the_generator_does_not_model_is_reported_absent():
    cs = world(count=6, copies=3)[2]
    assert cs["access-log:hosted-agent"].status == "absent"
    assert cs["access-log:watcher"].status == "absent"
    assert cs["orchestrator"].status == "absent"
    assert cs["access-log:witness"].status == "present"


def test_log_join_material_is_planted_only_when_asked():
    plain = world(count=6, copies=3)[2]
    planted = world(count=6, copies=3, log_join_material=True)[2]
    def count(cs, text):
        return sum(text in line.text for c in cs.of_kind("issuing-home") for line in c.logs)
    assert count(plain, "bulk issuance") == 0
    # Three even citizens are logged one line per copy; three odd ones as a trace: one header
    # naming the management AID, then one line per copy naming only its credential.
    assert count(planted, "bulk issuance for") == 3 * 3 + 3
    assert count(planted, "] issued credential") == 3 * 3
