"""The driver on live KERIA agencies: a small plan, run twice with one seed."""

import json
import re
from pathlib import Path

import pytest
from keri.core import serdering

from kpa_keria_stack import driver

pytestmark = pytest.mark.slow
ID = re.compile(r"(?<![A-Za-z0-9_-])[A-Z][A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
PLAN = {
    "seed": 11, "homes": 1, "verifiers": ["bar"], "attributes": ["age-band"],
    "dt_granularity": 0.0, "copies": 2,
    "citizens": [{"home": 0, "attributes": {"age-band": "21-29"}},
                 {"home": 0, "attributes": {"age-band": "65+"}}],
    # Mixed across citizens, as issuance_order = "mixed" orders it.
    "issuance": [{"citizen": 0, "copy": 0}, {"citizen": 1, "copy": 0},
                 {"citizen": 0, "copy": 1}, {"citizen": 1, "copy": 1}],
    "presentations": [{"citizen": 0, "copy": 1, "verifier": "bar"},
                      {"citizen": 1, "copy": 0, "verifier": "bar"},
                      {"citizen": 0, "copy": 0, "verifier": "bar"}],
}


def mine(work: Path) -> list[str]:
    """Processes whose command line names the work directory."""
    out = []
    for cmdline in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if str(work).encode() in cmdline.read_bytes():
                out.append(cmdline.parent.name)
        except OSError:
            pass
    return out


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    out = []
    for n in range(2):
        work = tmp_path_factory.mktemp(f"keria-{n}")
        out.append((driver.run(json.loads(json.dumps(PLAN)), work), work))
    return out


def messages(stream: str) -> list[dict]:
    out, at = [], stream.find('{"v":"')
    while at >= 0:
        serder = serdering.SerderKERI(raw=stream[at:].encode())
        out.append(serder.sad)
        at = stream.find('{"v":"', at + serder.size)
    return out


def test_no_agency_outlives_the_run(runs):
    for _, work in runs:
        assert mine(work) == []


def test_public_record_is_the_issuers_kel_and_its_registrys_tel(runs):
    export, _ = runs[0]
    issuer = export["issuers"][0]
    assert sorted(export["public"]) == [f"kel:{issuer['aid']}", f"tel:{issuer['registry']}"]
    kel = messages(export["public"][f"kel:{issuer['aid']}"])
    # inception, the registry's anchor, then one anchor per issuance: issuance_block is copies
    assert [e["t"] for e in kel] == ["icp", "ixn"] + ["ixn"] * 4
    anchored = [e["a"][0]["i"] for e in kel[2:]]
    assert anchored == [c["said"] for c in export["credentials"]]
    tel = messages(export["public"][f"tel:{issuer['registry']}"])
    assert [e["t"] for e in tel] == ["vcp"] + ["iss"] * 4
    assert [e["i"] for e in tel[1:]] == anchored


def test_issuance_follows_the_plan(runs):
    export, _ = runs[0]
    order = [(c["citizen"], c["copy"]) for c in export["credentials"]]
    assert order == [(s["citizen"], s["copy"]) for s in PLAN["issuance"]]
    for c in export["credentials"]:
        assert c["holder"] == export["citizens"][c["citizen"]]["holders"][c["copy"]]
    kinds = [k for k, _, _ in export["timeline"]]
    assert kinds == ["provision"] + ["issue"] * 4 + ["present"] * 3


def test_presentations_carry_the_grant_and_the_credential(runs):
    export, _ = runs[0]
    assert len(export["presentations"]) == 3
    for p, step in zip(export["presentations"], PLAN["presentations"], strict=True):
        assert (p["citizen"], p["copy"], p["verifier"]) == (step["citizen"], step["copy"], "bar")
        assert p["raw"].startswith('{"v":"KERI10JSON') and f'"d":"{p["grant"]}"' in p["raw"]
        assert f'"d":"{p["said"]}"' in p["raw"].split(p["grant"], 1)[1]
    verifier = export["verifiers"]["bar"]
    assert set(verifier["kels"]) == {p["holder"] for p in export["presentations"]}
    stored = {r["said"] for r in verifier["records"]["credentials"]}
    assert stored == {p["said"] for p in export["presentations"]}


def test_the_home_keys_each_credential_by_the_holders_agent(runs):
    export, _ = runs[0]
    rows = export["homes"][0]["records"]["credentials"]
    assert len(rows) == 4
    for row in rows:
        citizen = next(c for c in export["citizens"] if row["holder"] in c["holders"])
        assert row["management"] == citizen["agent"]
        assert row["a.age-band"] in ("21-29", "65+") and row["dt"]
    routes = sorted(r["route"] for r in export["homes"][0]["records"]["exchanges"])
    assert routes == ["/ipex/admit"] * 4 + ["/ipex/grant"] * 4


def test_every_identifier_exported_is_attributed(runs):
    export, _ = runs[0]
    known = set(export["artifacts"]) | set(export["nobody"])
    known |= {i for s in export["public"].values() for i in ID.findall(s)}
    texts = [json.dumps(h["records"]) for h in export["homes"]]
    texts += [line for h in export["homes"] for _, line in h["logs"]]
    texts += [json.dumps(v["records"]) for v in export["verifiers"].values()]
    texts += [line for v in export["verifiers"].values() for _, line in v["logs"]]
    texts += [json.dumps(export["wallet"]["records"])]
    texts += [line for _, line in export["wallet"]["logs"]]
    texts += [p["raw"] for p in export["presentations"]]
    unknown = {i for t in texts for i in ID.findall(t)} - known
    assert unknown == set()
    issuer = export["issuers"][0]
    assert {issuer["aid"], issuer["registry"]} <= set(export["nobody"])
    for n, citizen in enumerate(export["citizens"]):
        for aid in [citizen["agent"], citizen["controller"], *citizen["holders"]]:
            assert export["artifacts"][aid] == n
    for c in export["credentials"]:
        assert export["artifacts"][c["said"]] == c["citizen"]


def test_one_seed_gives_the_same_aids_but_not_the_same_bytes(runs):
    (a, _), (b, _) = runs
    assert a["issuers"][0]["aid"] == b["issuers"][0]["aid"]
    assert a["issuers"][0]["registry"] == b["issuers"][0]["registry"]
    assert [c["holders"] for c in a["citizens"]] == [c["holders"] for c in b["citizens"]]
    assert a["verifiers"]["bar"]["aid"] == b["verifiers"]["bar"]["aid"]
    assert [c["controller"] for c in a["citizens"]] == [c["controller"] for c in b["citizens"]]
    # Credentials carry the wall-clock issuance stamp, and KERIA incepts agents from fresh salt.
    assert {c["said"] for c in a["credentials"]}.isdisjoint(c["said"] for c in b["credentials"])
    assert a["citizens"][0]["agent"] != b["citizens"][0]["agent"]
