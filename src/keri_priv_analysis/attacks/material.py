"""Checks that a party's compartments hold an attack's material at all.

An attack that reads no material makes no joins, and that must not read as a clean result. Each
check returns what is lacking, in words, or None when the material is there.
"""

from __future__ import annotations

from ..model import CompartmentSet


def anything(cs: CompartmentSet) -> str | None:
    return None


def batches(cs: CompartmentSet) -> str | None:
    if any(n.startswith("batch:") for c in cs.of_kind("public") for n in c.streams):
        return None
    return "Registrar batches in the public record"


def holder_kels(cs: CompartmentSet) -> str | None:
    if any(n.startswith("kel:") for c in cs.of_kind("verifier") for n in c.streams):
        return None
    return "holder-AID KELs in a verifier's compartment"


def verifier_logs(cs: CompartmentSet) -> str | None:
    if any(line.text.startswith("first-seen ") for c in cs.of_kind("verifier")
           for line in c.logs):
        return None
    return "a verifier's own probe log"


def logs(name: str):
    def check(cs: CompartmentSet) -> str | None:
        if name in cs and cs[name].status == "present" and cs[name].logs:
            return None
        return f"log lines in {name}"
    check.__name__ = f"logs_{name}"
    return check


def end_roles(cs: CompartmentSet) -> str | None:
    if any(row.get("role") for c in cs.of_kind("verifier") for rows in c.records.values()
           for row in rows):
        return None
    return "end-role records in a verifier's compartment"
