import dataclasses
from pathlib import Path

import pytest
from bakobo.errors import BakoboError
from keri_priv_analysis.scenario import load

from kpa_adapter_keria import settings
from kpa_adapter_keria.settings import FREE, HONOURED

ROOT = Path(__file__).resolve().parents[1]

# One value per setting that KERIA does not honour.
REFUSED = {
    "registry_scope": "credential", "registry_allocation": "random", "tel_updates": "bup",
    "status_updates": "lockstep", "batch_size": 4, "publication_window": 3600.0,
    "holder_network": "mixed", "holder_status_reads": True, "hosted_agents": "shared",
    "verifier_probing": True, "identity_oracle": True, "sealed_revocation_map": True,
    "decoys": 3, "log_join_material": True, "holder_aids": "delegated",
    "holder_witnesses": "per-citizen", "copy_template": "cloned-attributes",
    "first_seen": "constant", "anchor_order": "shuffled",
}


def test_every_stack_setting_is_classified(scenario):
    names = {f.name for f in dataclasses.fields(scenario.stack)}
    assert names == set(HONOURED) | set(FREE)
    assert set(REFUSED) == {s for s, (allowed, _) in HONOURED.items()
                            if s != "issuance_order"}


def test_the_contract_and_smoke_scenarios_ask_only_for_what_keria_honours(scenario):
    settings.check(scenario.stack)
    settings.check_disclosure(scenario)
    smoke = load(ROOT / "scenarios" / "smoke.toml")
    settings.check(smoke.stack)
    settings.check_disclosure(smoke)
    assert (smoke.citizens.count, smoke.citizens.copies) == (200, 2)


@pytest.mark.parametrize("setting", sorted(REFUSED))
def test_each_unsupported_setting_is_refused(scenario, setting):
    stack = dataclasses.replace(scenario.stack, **{setting: REFUSED[setting]})
    with pytest.raises(BakoboError) as exc:
        settings.check(stack)
    assert exc.value.code == "e.feature.unsupported.stack-setting.f"
    assert setting in str(exc.value) and "keria" in str(exc.value)


def test_both_issuance_orders_and_any_granularity_are_honoured(scenario):
    for order in ("per-citizen", "mixed"):
        settings.check(dataclasses.replace(scenario.stack, issuance_order=order,
                                           dt_granularity=86400.0))


def test_a_presentation_disclosing_less_than_the_credential_is_refused(scenario):
    settings.check_disclosure(scenario)
    first = dataclasses.replace(scenario.presentations[0], disclose=("age-band",))
    partial = dataclasses.replace(scenario, presentations=(first, *scenario.presentations[1:]))
    with pytest.raises(BakoboError) as exc:
        settings.check_disclosure(partial)
    assert exc.value.code == "e.feature.unsupported.stack-setting.f"
    assert "presentation[0].disclose" in str(exc.value)
