"""The report, generated from a run directory's results.json and nothing else.

It states joins, bits, completeness and cost, names an owner for every failing claim, and ends
with the non-claims. It never says "unlinkable" (this.i 8q5ylk4q); write() refuses to emit a
report that does.
"""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

from . import errors
from .catalogue import gaps, non_claims

FORBIDDEN = re.compile(r"unlinkab", re.IGNORECASE)
VERIFIER_BITS_LIMIT = (
    "Verifier-side bits are a lower bound on what presentation bytes can reveal: "
    "the scorer counts declared attributes, while a selectively disclosed age-band "
    "presentation can carry a full birthDate (tick 6hat)."
)


def _n(value) -> str:
    if value is None:
        return "not measured"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".") if value != int(value) else str(int(value))
    return str(value)


def _quantile(values, q):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))] if ordered else 0.0


def summarize(results: dict) -> dict:
    """The structured report: verdicts with their causes and owners, and each party's numbers."""
    limits = list(results["provenance"]["adapter"].get("limitations", []))
    if not any(item.startswith("Verifier-side bits are a lower bound") for item in limits):
        limits.insert(0, VERIFIER_BITS_LIMIT)
    claims = []
    for c in results["claims"]:
        entry = {k: c[k] for k in ("party", "metric", "op", "threshold", "measured", "verdict")}
        if c["verdict"] == "fail":
            entry["attacks"] = [{"attack": a, "cause": results["causes"].get(a, ""),
                                 "owner": results["owners"].get(a, "")} for a in c["attacks"]]
        claims.append(entry)
    parties = {}
    for name, p in results["parties"].items():
        s = p["score"]
        bits = s["bits"]
        completeness = {}
        for domain, per in sorted(s["completeness"].items()):
            values = list(per.values())
            completeness[domain] = {"median": statistics.median(values) if values else 0.0,
                                    "complete": sum(1 for v in values if v == 1.0),
                                    "flagged": domain in s["flagged"],
                                    "mandatory": s["flagged"].get(domain)}
        parties[name] = {
            "kind": p["kind"],
            "compartments": p["compartments"],
            "notes": p["notes"],
            "attacks": {a: ({"joins": r["joins"], "observations": r["observations"],
                             "precision": r["score"]["precision"],
                             "certain_share": r["score"]["certain_share"],
                             "reidentified": r["score"]["reidentified"]}
                            if r["measured"] else {"not_measured": r["missing"]})
                        for a, r in p["attacks"].items()},
            "joins": s["joins"],
            "precision": s["precision"],
            "recall": s["recall"],
            "bits": {"median": statistics.median(bits) if bits else 0.0,
                     "p90": _quantile(bits, 0.9), "max": max(bits, default=0.0),
                     "threshold": s["threshold_bits"]},
            "citizens": len(bits),
            "reidentified": s["reidentified"],
            "sensitive_exposed": s["sensitive_exposed"],
            "identity_exposed": s["identity_exposed"],
            "completeness": completeness,
            "bound_joins": s["bound_joins"],
            "breach_reidentified": s["breach_reidentified"],
            "increment": {"median": statistics.median(s["increment"]) if s["increment"] else 0.0,
                          "max": max(s["increment"], default=0.0)},
        }
    return {"provenance": results["provenance"], "claims": claims, "parties": parties,
            "measurement_limits": limits,
            "gaps": gaps(), "non_claims": non_claims()}


def render(summary: dict) -> str:
    prov = summary["provenance"]
    out = ["# Privacy analysis report", ""]
    out += [(f"Scenario `{prov['scenario_sha256']}`, run on the {prov['adapter']['name']} adapter "
            f"with suite {prov['suite']} and keripy {prov['keripy']['version']} "
            f"({prov['keripy']['commit'] or 'commit unknown'}). The population has "
            f"{prov['population']['size']} rows (seed {prov['population']['seed']}, sha256 "
            f"`{prov['population']['sha256']}`)."), ""]
    out += ["## Measurement limits", "",
            *(f"- {item}" for item in summary["measurement_limits"]), ""]
    out += ["## Claims", "", "| Party | Claim | Measured | Verdict |", "|---|---|---|---|"]
    for c in summary["claims"]:
        out.append(f"| {c['party']} | {c['metric']} {c['op']} {_n(c['threshold'])} | "
                   f"{_n(c['measured'])} | {c['verdict']} |")
    failures = [c for c in summary["claims"] if c["verdict"] == "fail"]
    if failures:
        out += ["", "## Failures", ""]
        for c in failures:
            out.append(f"{c['party']}: {c['metric']} {c['op']} {_n(c['threshold'])} fails at "
                       f"{_n(c['measured'])}.")
            if not c["attacks"]:
                out.append("No single attack fails it; the attacks fail it only in combination.")
            for a in c["attacks"]:
                out.append(f"- {a['attack']} fails it alone. Cause: {a['cause'] or 'not stated by '
                           'the adapter'}. Owner: {a['owner']}.")
            out.append("")
    out += ["", "## Parties", ""]
    for name, p in summary["parties"].items():
        out += [f"### {name} ({p['kind']})", ""]
        held = ", ".join(f"{c} ({s})" if s != "present" else c
                         for c, s in p["compartments"].items())
        out.append(f"Holds: {held}.")
        for c, note in p["notes"].items():
            out.append(f"- {c}: {note}")
        out += ["", "| Attack | Joins | Precision | Certain | Re-identified alone |",
                "|---|---|---|---|---|"]
        for a, r in p["attacks"].items():
            if "not_measured" in r:
                out.append(f"| {a} | not measured: needs {'; '.join(r['not_measured'])} | | | |")
            else:
                joins = r["joins"] if r["joins"] or not r["observations"] else \
                    f"{r['observations']} observations"
                out.append(f"| {a} | {joins} | {_n(r['precision'])} | "
                           f"{_n(r['certain_share'])} | {r['reidentified']} |")
        b = p["bits"]
        out += ["", (f"All attacks together make {p['joins']} joins, precision "
                f"{_n(p['precision'])}, recall {_n(p['recall'])}. Citizens at or above the "
                f"re-identification threshold of {_n(b['threshold'])} bits: {p['reidentified']} "
                f"of {p['citizens']};"
                f" median {_n(b['median'])} bits, 90th percentile "
                f"{_n(b['p90'])}, maximum {_n(b['max'])}.")]
        if p["sensitive_exposed"]:
            attached = ", ".join(f"{a} ({n})" for a, n in sorted(p["sensitive_exposed"].items()))
            out.append(f"Sensitive attributes attached to re-identified citizens: {attached}.")
        out.append(f"Citizens whose legal identity is joined to an identifier issued to them: "
                   f"{p['identity_exposed']}.")
        for domain, c in p["completeness"].items():
            flag = ""
            if c["flagged"]:
                flag = (" Flagged: the party provably holds every event of some citizen in this "
                        f"domain, and use {'is' if c['mandatory'] else 'is not'} mandatory.")
            out.append(f"Completeness in {domain}: median {_n(c['median'])}; citizens with every "
                       f"event in one cluster: {c['complete']}.{flag}")
        out.append(f"Joins its accepted terms forbid: {p['bound_joins']}; a breach of those terms "
                   f"would re-identify {p['breach_reidentified']}.")
        out += [(f"Bits the protocol adds over the party's own context: median "
                f"{_n(p['increment']['median'])}, maximum {_n(p['increment']['max'])}."), ""]
    out += ["## Attacks the catalogue does not yet make", "",
            ("Silence on these channels is not a result. Each is tracked in this repository's tick "
            "ledger."), ""]
    out += [f"- {text} (tick {tick})" for tick, text in sorted(summary["gaps"].items())]
    out += ["", "## What this report does not claim", ""]
    out += [f"- {item}" for item in summary["non_claims"]]
    return "\n".join(out) + "\n"


def write(run: Path) -> None:
    run = Path(run)
    summary = summarize(json.loads((run / "results.json").read_text()))
    text = render(summary)
    encoded = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    for rendered, source in ((text, "report.md"), (encoded, "report.json")):
        found = FORBIDDEN.search(rendered)
        if found:
            raise errors.REPORT_WORD(word=found.group(0), source=source)
    (run / "report.md").write_text(text)
    (run / "report.json").write_text(encoded)
