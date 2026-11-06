import hashlib
import subprocess
import tomllib

import pytest
from bakobo.errors import BakoboError
from keri_priv_analysis.attacks import CATALOGUE
from keri_priv_analysis.catalogue import owners as catalogue_owners

from kpa_adapter_keria import adapter
from kpa_adapter_keria.adapter import Adapter


def test_the_entry_point_names_this_adapter():
    from keri_priv_analysis.runner import adapter_for

    assert isinstance(adapter_for("keria"), Adapter) and Adapter.name == "keria"


def test_provenance_names_every_pinned_component():
    prov = Adapter().provenance()
    raw = adapter.MANIFEST.read_bytes()
    assert prov["manifest_sha256"] == hashlib.sha256(raw).hexdigest()
    names = {c["name"] for c in prov["components"]}
    assert names == {"keria", "signifypy", "keripy", "hio"}
    for c in tomllib.loads(raw.decode())["component"]:
        assert len(c["commit"]) == 40 and c["repository"].startswith("https://github.com/")
    assert len(prov["stack_lock_sha256"]) == 64 and prov["kind"] == "real"


def test_causes_cover_the_catalogue(scenario):
    causes = Adapter().causes(scenario)
    assert set(causes) == {a.name for a in CATALOGUE}
    assert "credentialing.py:735" in causes["shared-registry"]
    assert "end role" in causes["agent-end-role"]
    assert causes["shared-batch-root"] == adapter.NOT_PRODUCED


def test_failed_claim_owners_name_the_keria_stack():
    owners = Adapter().owners()
    assert set(owners) == {a.name for a in CATALOGUE}
    assert "SignifyPy" in owners["shared-registry"]
    assert "KERIA" in owners["agent-end-role"]
    assert not set(owners.values()) & set(catalogue_owners().values())


def test_without_uv_the_stack_cannot_run(monkeypatch, tmp_path):
    monkeypatch.setattr(adapter.shutil, "which", lambda name: None)
    with pytest.raises(BakoboError) as exc:
        adapter.run_stack({}, tmp_path)
    assert exc.value.code == "e.env.keria.uv.f"


def test_a_failed_stack_run_is_reported_with_its_output(monkeypatch, tmp_path):
    seen = {}

    def fail(cmd, env, capture_output, text, check):
        seen["cmd"], seen["env"] = cmd, env
        return subprocess.CompletedProcess(cmd, 3, stdout="x" * 5000, stderr="boom")

    monkeypatch.setenv("VIRTUAL_ENV", "/somewhere")
    monkeypatch.setattr(adapter.subprocess, "run", fail)
    with pytest.raises(BakoboError) as exc:
        adapter.run_stack({"seed": 1}, tmp_path)
    assert exc.value.code == "e.env.keria.driver.r" and "boom" in str(exc.value)
    assert "VIRTUAL_ENV" not in seen["env"]
    assert seen["cmd"][1:5] == ["run", "--project", str(adapter.STACK), "--locked"]
    assert (tmp_path / "plan.json").read_text() == '{"seed": 1}'


def test_run_refuses_before_starting_anything(scenario, population, monkeypatch):
    import dataclasses

    monkeypatch.setattr(adapter, "run_stack", lambda plan, work: pytest.fail("ran"))
    bad = dataclasses.replace(scenario, stack=dataclasses.replace(scenario.stack, decoys=1))
    with pytest.raises(BakoboError):
        Adapter().run(bad, population)
    first = dataclasses.replace(scenario.presentations[0], disclose=("county",))
    partial = dataclasses.replace(scenario, presentations=(first, *scenario.presentations[1:]))
    with pytest.raises(BakoboError):
        Adapter().run(partial, population)


def test_run_removes_its_work_directory(scenario, population, monkeypatch, tmp_path):
    seen = []
    monkeypatch.setenv(adapter.WORK, str(tmp_path))

    def stack(plan, work):
        seen.append(work)
        raise RuntimeError("stack down")

    monkeypatch.setattr(adapter, "run_stack", stack)
    with pytest.raises(RuntimeError):
        Adapter().run(scenario, population)
    assert seen[0].parent == tmp_path and not seen[0].exists()
