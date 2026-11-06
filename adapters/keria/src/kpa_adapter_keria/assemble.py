"""Build the suite's compartments, ground truth and knowledge from what the KERIA driver exported.

The driver read each host's stores and logs after the host stopped. This module only places them:
it puts each host's contents in the compartment that host's access boundary is, moves wall-clock
times onto the scenario's clock, and names whose each identifier is from the driver's attribution.
"""

from __future__ import annotations

from keri_priv_analysis.model import (
    Compartment,
    CompartmentSet,
    GroundTruth,
    Knowledge,
    LogLine,
    Presentation,
)
from keri_priv_analysis.scenario import Scenario

from .clock import Clock
from .plan import Plan

ABSENT = {
    "orchestrator": "KERIA has no orchestrator: the issuer's Signify client drives issuance "
    "itself, one request at a time.",
    "operation-log": "KERIA keeps each agent's long-running operations in its own host's stores, "
    "so they belong to that host's compartment rather than to a separate operation log; the "
    "adapter does not export them.",
    "revocation-authority": "KERIA has no revocation authority: the issuer's own agent holds "
    "every credential it issued and would revoke it.",
    "identity-proofing": "KERIA has no identity proofing, so no store joins a legal identity to "
    "an identifier.",
    "access-log:witness": "Every AID is witnessless, so no witness runs.",
    "access-log:registrar": "KERIA has no Registrar.",
    "access-log:observer": "KERIA has no Observer: a verifier reads TEL state from the issuer's "
    "agent through the holder's presentation.",
    "access-log:watcher": "No watcher runs.",
    "access-log:holder-witness": "Holder AIDs are witnessless, so no witness serves them.",
    "access-log:mailbox": "KERIA agents are their own mailboxes: the messages a holder receives "
    "arrive at its hosted agent, whose log is access-log:hosted-agent.",
}
HOSTED_NOTE = ("The citizens' wallet host: one KERIA agency hosting one agent per citizen. Its "
               "log is what KERIA writes at INFO with request logging on, which records each "
               "request's path but not the address it came from, so every line's source is the "
               "host's own address. Its records are the agents' own stores.")


def _logs(lines, address: str, clock: Clock) -> list[LogLine]:
    return [LogLine(clock.at_second(wall), address, text) for wall, text in lines]


def _timed(rows, clock: Clock, times: dict[str, float] | None = None) -> list[dict[str, str]]:
    """Rows with a scenario `time`: an issued or presented credential's own time, else the time
    its dt stamp falls in. The stack's own dt is kept beside it."""
    out = []
    for row in rows:
        row = dict(row)
        if times is not None and row.get("said") in times:
            row["time"] = repr(times[row["said"]])
        elif row.get("dt"):
            row["time"] = repr(clock.at_stamp(row["dt"]))
        out.append(row)
    return out


def assemble(scenario: Scenario, plan: Plan, export: dict, population):
    clock = Clock(export["timeline"], plan)
    issued = {}
    for n, cred in enumerate(export["credentials"]):
        issued[cred["said"]] = plan.issuance[n].time
    shown = {}
    presentations: dict[str, list[Presentation]] = {v: [] for v in scenario.verifiers}
    truth_presentations, domains = {}, {}
    for n, p in enumerate(export["presentations"]):
        showing = plan.showings[n]
        row = population.row(plan.rows[showing.citizen])
        presentations[p["verifier"]].append(Presentation(
            handle=showing.handle, verifier=p["verifier"], time=showing.time,
            domain=showing.domain, disclosed={a: row[a] for a in showing.disclose},
            said=p["said"], registry=p["registry"], issuer=p["issuer"], holder=p["holder"],
            raw=p["raw"].encode()))
        shown[p["said"]] = showing.time
        truth_presentations[showing.handle] = showing.citizen
        domains[showing.handle] = showing.domain

    compartments = [Compartment(name="public", status="present",
                                streams={k: v.encode() for k, v in export["public"].items()})]
    for v in scenario.verifiers:
        x = export["verifiers"][v]
        compartments.append(Compartment(
            name=f"verifier:{v}", status="present", presentations=presentations[v],
            streams={f"kel:{pre}": kel.encode() for pre, kel in x["kels"].items()},
            records={name: _timed(rows, clock, shown) for name, rows in x["records"].items()},
            logs=_logs(x["logs"], x["address"], clock),
            note="One KERIA agency hosting the verifier's agent: its stores and its log."))
    for h, home in enumerate(export["homes"]):
        compartments.append(Compartment(
            name=f"issuing-home:{h}", status="present",
            records={name: _timed(rows, clock, issued) for name, rows in home["records"].items()},
            logs=_logs(home["logs"], home["address"], clock),
            note="One KERIA agency hosting the issuer's agent: its stores and its log. A "
            "credential row's management is the holder's agent AID, read from the end-role "
            "record the holder's OOBI left; KERIA has no management AID, and one agent serves "
            "all of a citizen's AIDs."))
    for name, note in ABSENT.items():
        compartments.append(Compartment(name=name, status="absent", note=note))
    wallet = export["wallet"]
    compartments.append(Compartment(
        name="access-log:hosted-agent", status="present",
        records={name: _timed(rows, clock, issued) for name, rows in wallet["records"].items()},
        logs=_logs(wallet["logs"], wallet["address"], clock), note=HOSTED_NOTE))

    truth = GroundTruth(
        citizen_rows=plan.rows,
        presentations=truth_presentations,
        identities={},
        artifacts=dict(export["artifacts"]),
        domains=domains,
        decoys=[],
    )
    knowledge = Knowledge(
        copies=scenario.citizens.copies,
        # One citizen's session issues one credential per copy, each anchored alone.
        per_citizen=scenario.citizens.copies,
        issuance_block=scenario.citizens.copies,
        issuers={i["aid"]: str(h) for h, i in enumerate(export["issuers"])},
        verifier_addresses={x["address"]: v for v, x in export["verifiers"].items()},
        service_addresses=[home["address"] for home in export["homes"]] + [wallet["address"]],
        # Every identifier the driver found to be no citizen's: the issuers', verifiers' and
        # agencies' AIDs, controllers and events, the registries and the schema.
        infrastructure=list(export["nobody"]),
    )
    return CompartmentSet(compartments), truth, knowledge
