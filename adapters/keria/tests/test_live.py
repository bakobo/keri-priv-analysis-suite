"""The adapter on the live KERIA stack: the contract suite on scenarios/contract.toml, and the
stack project's own tests, which hold the driver to 100% branch coverage in its environment."""

import shutil
import subprocess
import time

import pytest
from keri_priv_analysis import cesr, contract

from kpa_adapter_keria import adapter
from kpa_adapter_keria.adapter import Adapter

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def world(scenario, population):
    started = time.monotonic()
    out = Adapter().run(scenario, population)
    print(f"contract scenario on KERIA: {time.monotonic() - started:.0f} s")
    return out


def test_the_contract_suite_passes(scenario, population, world):
    assert contract.check(scenario, *world, population) == []


def test_one_citizen_session_anchors_one_event_per_copy(scenario, world):
    cs, truth, knowledge = world
    (kel,) = (s for n, s in cs["public"].streams.items() if n.startswith("kel:"))
    events = cesr.messages(kel)
    anchors = [e for e in events if e["t"] == "ixn"]
    # one anchor for the registry, then one per issued copy
    assert len(anchors) == 1 + scenario.citizens.count * knowledge.issuance_block
    issued = [e["a"][0]["i"] for e in anchors[1:]]
    citizens = [truth.artifacts[s] for s in issued]
    block = knowledge.issuance_block
    assert all(len(set(citizens[i:i + block])) == 1 for i in range(0, len(citizens), block))


def test_every_presentation_is_a_grant_followed_by_its_credential(world):
    cs, _, _ = world
    for p in cs.presentations():
        kinds = [m.get("t", "acdc") for m in cesr.messages(p.raw)]
        assert kinds == ["exn", "acdc"]


def test_the_stack_projects_own_suite_passes():
    done = subprocess.run([shutil.which("uv"), "run", "--project", str(adapter.STACK),
                           "--locked", "pytest", "-q", "-p", "no:cacheprovider",
                           str(adapter.STACK / "tests")], cwd=adapter.STACK, check=False,
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-2000:]
