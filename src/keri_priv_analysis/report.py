"""The report, generated from a run directory's results.json and nothing else.

It says first, in plain words, what each adversary learns, then each claim as a sentence, then
the cause and owner of every failing claim, and ends with the non-claims. Every party, attack and
column is named in words and linked to its explanation (explain.py, this.i 6r9sjucj). It never
says "unlinkable" (this.i 8q5ylk4q); write() refuses to emit a report that does.
"""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path

from . import errors, explain
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


def _party_link(name: str) -> str:
    title = explain.party_title(name)
    heading = f"{title} ({name})" if title != name else name
    return f"[{title}](#{explain.slug(heading)})"


def _claim_sentence(c: dict) -> str:
    """A claim as a sentence. A zero claim's text is a verb phrase ("re-identifies no one"); any
    other is a quantity and a bound ("the most bits ... is at most 10")."""
    phrase = explain.claim(c["metric"], c["op"], c["threshold"])
    if c["op"] == "<=" and c["threshold"] == 0:
        return f"The party {phrase}."
    return f"For the party, {phrase}."


def _complete(p: dict) -> str:
    """Citizens whose every use of a kind the party ties into one cluster. Proven means at least
    one such citizen's cluster rests on certain correlations, which is what flags a domain; an
    unproven one may rest on likelihood."""
    parts = [f"{c['complete']} of {p['citizens']} in {domain}, "
             f"{'proven' if c['flagged'] else 'not proven'}"
             for domain, c in p["completeness"].items() if c["complete"]]
    return ("ties all of some citizens' uses of a kind together: " + "; ".join(parts)
            if parts else "ties no citizen's uses of any kind all together")


def _summary_line(name: str, p: dict, claims: list[dict]) -> str:
    verdicts = [c["verdict"] for c in claims if c["party"] == name]
    tally = ", ".join(f"{verdicts.count(v)} {explain.verdict(v)}"
                      for v in ("fail", "pass", "not-measured") if verdicts.count(v))
    absent = [c for c, status in p["compartments"].items() if status == "absent"]
    # Anything but present or absent was not read; a status the contract does not name is shown
    # rather than dropped.
    unexported = [explain.compartment(c)
                  + ("" if status == "not-measured" else f" (status {status!r})")
                  for c, status in p["compartments"].items()
                  if status not in ("present", "absent")]
    line = (f"- {_party_link(name)}: {p['joins']} correlations, precision "
            f"{_n(p['precision'])}")
    if p["bound_joins"]:
        line += (f", of which its accepted terms forbid {p['bound_joins']} and so are not counted "
                 f"as harm (a breach would re-identify {p['breach_reidentified']})")
    line += (f"; re-identifies {p['reidentified']} of {p['citizens']} citizens; attaches a legal "
             f"identity to {p['identity_exposed']}; {_complete(p)}.")
    if absent:
        line += (" This stack does not have " + " or ".join(explain.compartment(c) for c in absent)
                 + ", so the party was measured on the rest of what it would hold.")
    if unexported:
        line += (" The adapter could not export " + " or ".join(unexported)
                 + ", so what they hold is not measured.")
    return line + (f" Claims: {tally}." if tally else "")


def render(summary: dict) -> str:
    prov = summary["provenance"]
    T = explain.term
    out = [f"# Privacy analysis: {prov['adapter']['name']} adapter", ""]
    out += [("This report says what each adversary in one scenario could learn about simulated "
             "citizens by correlating the data it holds, and whether each claim written before "
             f"the run held. [How to read it]({explain.SITE}reading-a-report/), and the "
             f"[glossary]({explain.SITE}glossary/) for any term."), ""]
    out += [(f"Scenario `{prov['scenario_sha256']}`, run on the {prov['adapter']['name']} adapter "
            f"with suite {prov['suite']} and keripy {prov['keripy']['version']} "
            f"({prov['keripy']['commit'] or 'commit unknown'}). The population has "
            f"{prov['population']['size']} rows (seed {prov['population']['seed']}, sha256 "
            f"`{prov['population']['sha256']}`)."), ""]
    out += ["## What each adversary learns", "",
            *(_summary_line(name, p, summary["claims"]) for name, p in summary["parties"].items()),
            ""]
    out += ["## Claims", "",
            "Each claim was written into the scenario before the run.", "",
            f"| Party | Claim | Measured | {T('verdict', 'Verdict')} |", "|---|---|---|---|"]
    for c in summary["claims"]:
        out.append(f"| {_party_link(c['party'])} | {_claim_sentence(c)} | {_n(c['measured'])} | "
                   f"{explain.verdict(c['verdict'])} |")
    failures = [c for c in summary["claims"] if c["verdict"] == "fail"]
    if failures:
        out += ["", "## Why claims fail", ""]
        for c in failures:
            sentence = _claim_sentence(c)
            out.append(f"{_party_link(c['party'])}. Claim: {sentence[0].lower()}{sentence[1:]} "
                       f"It fails: measured {_n(c['measured'])}.")
            out.append("")
            if not c["attacks"]:
                out.append("No single attack fails it; the attacks fail it only in combination.")
            for a in c["attacks"]:
                out.append(f"- {explain.attack_link(a['attack'])} is enough on its own. Cause: "
                           f"{a['cause'] or 'not stated by the adapter'}. Owner: {a['owner']}.")
            out.append("")
    out += ["", "## Measurement limits", "",
            *(f"- {item}" for item in summary["measurement_limits"]), ""]
    out += ["## Parties", ""]
    for name, p in summary["parties"].items():
        title = explain.party_title(name)
        out += [f"### {title} ({name})" if title != name else f"### {name}", ""]
        held = ", ".join(explain.compartment_link(c) + (f" ({explain.verdict(s)})"
                                                       if s != "present" else "")
                         for c, s in p["compartments"].items())
        out += [f"{explain.party_kind(p['kind'])} This party holds {held}.", ""]
        if p["notes"]:
            out += ["What the adapter put in each:", ""]
            out += [f"- {explain.compartment(c)}: {note}" for c, note in p["notes"].items()]
            out.append("")
        out += [(f"| {T('attack', 'Attack')} | {T('correlation', 'Correlations')} | "
                 f"{T('precision', 'Precision')} | {T('certain', 'Certain')} | "
                 f"{T('reidentified', 'Re-identified alone')} |"), "|---|---|---|---|---|"]
        for a, r in p["attacks"].items():
            link = explain.attack_link(a)
            if "not_measured" in r:
                lacking = "; ".join(explain.needs(item) for item in r["not_measured"])
                out.append(f"| {link} | not measured: needs {lacking} | | | |")
            else:
                joins = r["joins"] if r["joins"] or not r["observations"] else \
                    f"{r['observations']} observations"
                out.append(f"| {link} | {joins} | {_n(r['precision'])} | "
                           f"{_n(r['certain_share'])} | {r['reidentified']} |")
        b = p["bits"]
        out += ["", (f"All attacks together make {p['joins']} "
                     f"{T('correlation', 'correlations')}, {T('precision', 'precision')} "
                     f"{_n(p['precision'])}, {T('recall', 'recall')} {_n(p['recall'])}. "
                     f"{T('reidentified', 'Re-identified')} citizens, those at or above "
                     f"{_n(b['threshold'])} {T('bits', 'identifying bits')}: {p['reidentified']} "
                     f"of {p['citizens']}; median {_n(b['median'])} bits, 90th percentile "
                     f"{_n(b['p90'])}, maximum {_n(b['max'])}.")]
        if p["sensitive_exposed"]:
            attached = ", ".join(f"{a} ({n})" for a, n in sorted(p["sensitive_exposed"].items()))
            out.append(f"Sensitive attributes attached to re-identified citizens: {attached}.")
        out.append(f"Citizens whose legal identity it attaches to an identifier issued to them: "
                   f"{p['identity_exposed']}.")
        for domain, c in p["completeness"].items():
            flag = ""
            if c["flagged"]:
                flag = (" Flagged: the party can prove it holds every one of some citizen's uses "
                        f"of this kind, and use {'is' if c['mandatory'] else 'is not'} mandatory.")
            out.append(f"{T('completeness', 'Completeness')} in {domain}: median "
                       f"{_n(c['median'])}; citizens with every use tied together: "
                       f"{c['complete']}.{flag}")
        out.append(f"Correlations its accepted terms forbid: {p['bound_joins']}; a breach of "
                   f"those terms would re-identify {p['breach_reidentified']}.")
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
