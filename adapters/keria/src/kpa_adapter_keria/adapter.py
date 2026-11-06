"""The KERIA adapter: run a scenario on KERIA agents driven by SignifyPy, and hand the suite what
every host stored (docs/adapters.md).

KERIA and SignifyPy need keripy 1.2, and the suite needs keripy 2; both are the package `keri`, so
they cannot share an environment. The adapter therefore runs the stack as a child process in its
own uv project, adapters/keria/stack, handing it a plan and reading back a JSON export of each
host's stores and logs. Attacks still read only the compartments built from that export.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

from . import errors, settings
from .assemble import assemble
from .plan import build

ROOT = Path(__file__).resolve().parents[2]
STACK = ROOT / "stack"
MANIFEST = ROOT / "manifest.toml"
TAIL = 2000
# The directory the stack's hosts are created under; the system's temporary directory by default.
WORK = "KPA_KERIA_WORK"

# Where each attack's leak comes from in this stack, as file:line in the pinned sources.
SIGNIFY = "signifypy 2e9772cb signify/app/credentialing.py"
KERIA = "keria 928ce26a src/keria"
KERIPY = "keripy bab95c16 src/keri"
CAUSES = {
    "shared-registry": f"{SIGNIFY}:735 issues every credential into the issuer's one named "
    "registry (status=regk)",
    "kel-anchor-adjacency": f"{SIGNIFY}:759 anchors each issuance in the issuer's next "
    "interaction event, as issued",
    "registry-inception-adjacency": "one registry per issuer, incepted once before issuance",
    "timestamp-clustering": f"{SIGNIFY}:738 stamps the credential and its iss event with the "
    "client's clock, to the microsecond",
    "kel-first-seen": f"{KERIPY}/core/eventing.py:3131 stamps each KEL event's first-seen time "
    "from the wall clock, and the KEL replay carries it",
    "custodial-join": f"{KERIPY}/vdr/verifying.py:300 and :305 index every credential by issuer "
    f"and subject, and {KERIPY}/core/eventing.py:4778 keeps each holder AID's agent end role",
    "hosted-agent": f"{KERIA}/app/agenting.py:362 boots one agent per controller, serving all of "
    "a citizen's AIDs",
    "agent-end-role": f"{KERIPY}/core/eventing.py:4778 retains each holder AID's agent "
    f"end role; {KERIA}/app/agenting.py:362 serves the same citizen's AIDs from one agent",
    "log-scan": f"{KERIA}/app/agenting.py:1109 logs the first 1024 bytes of every message an "
    f"agent receives, and {KERIA}/core/httping.py:81 every request path",
}
NOT_PRODUCED = "this stack does not produce the vector under the settings it honours"
OWNERS = {
    "shared-registry": "SignifyPy issuance and the KERIA issuer's registry policy",
    "kel-anchor-adjacency": "SignifyPy issuance and the KERIA issuer",
    "registry-inception-adjacency": "the KERIA issuer's registry policy",
    "timestamp-clustering": "SignifyPy issuance and the KERIA issuer",
    "kel-first-seen": "KERIA's keripy event store",
    "custodial-join": "KERIA's credential and agent stores",
    "hosted-agent": "the KERIA hosted-agent operator",
    "agent-end-role": "the KERIA hosted-agent operator and SignifyPy holder",
    "log-scan": "the KERIA agent and API operators",
}


def run_stack(plan: dict, work: Path) -> dict:
    """Run the plan in the stack's own environment and return its export."""
    uv = shutil.which("uv")
    if uv is None:
        raise errors.UV_MISSING()
    (work / "plan.json").write_text(json.dumps(plan))
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "PYTHONPATH")}
    done = subprocess.run(
        [uv, "run", "--project", str(STACK), "--locked", "--quiet", "python", "-m",
         "kpa_keria_stack", str(work / "plan.json"), str(work / "export.json"),
         str(work / "hosts")],
        env=env, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise errors.STACK_FAILED(code=done.returncode,
                                  tail=(done.stdout + done.stderr)[-TAIL:])
    return json.loads((work / "export.json").read_text())


class Adapter:
    name = "keria"

    def run(self, scenario, population):
        settings.check(scenario.stack)
        settings.check_disclosure(scenario)
        plan = build(scenario, population)
        work = Path(tempfile.mkdtemp(prefix="kpa-keria-", dir=os.environ.get(WORK)))
        try:
            export = run_stack(plan.driver, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return assemble(scenario, plan, export, population)

    def provenance(self) -> dict:
        raw = MANIFEST.read_bytes()
        return {"kind": "real", "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "components": tomllib.loads(raw.decode())["component"],
                "stack_lock_sha256": hashlib.sha256((STACK / "uv.lock").read_bytes()).hexdigest(),
                "note": "KERIA agents driven by SignifyPy in their own environment; witnessless "
                "AIDs; actions performed in scenario order and placed at scenario times, with "
                "the stack's own wall-clock stamps kept in the bytes and lines"}

    def causes(self, scenario) -> dict[str, str]:
        from keri_priv_analysis.attacks import CATALOGUE

        return {a.name: CAUSES.get(a.name, NOT_PRODUCED) for a in CATALOGUE}

    def owners(self) -> dict[str, str]:
        from keri_priv_analysis.attacks import CATALOGUE

        return {a.name: OWNERS.get(a.name, "the KERIA and SignifyPy operators")
                for a in CATALOGUE}
