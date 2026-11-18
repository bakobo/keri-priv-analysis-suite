"""Plain-language explanations of what a report names (this.i 6r9sjucj), read from
data/explanations.toml so a term is explained once for the report, the site and GitHub.

Every helper falls back to the id it was given when it has no explanation, so a report never
fails for want of prose; tests/test_explain.py is what keeps the explanations complete.
"""

from __future__ import annotations

import re
import tomllib
from functools import cache
from importlib.resources import files


@cache
def data() -> dict:
    return tomllib.loads(files(__package__).joinpath("data/explanations.toml").read_text())


SITE = data()["site"]

_OPS = {"<=": "at most", ">=": "at least", "<": "less than", ">": "more than", "==": "exactly"}
def _number(value: float) -> str:
    return str(int(value)) if value == int(value) else f"{value:g}"


def hover(text: str) -> str:
    """`text` safe as a markdown link title, which a double quote would end."""
    return text.replace('"', "'")


def slug(heading: str) -> str:
    """The anchor the site's table of contents gives `heading` (Python-Markdown's toc slugify)."""
    value = re.sub(r"[^\w\s-]", "", heading).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def party_title(name: str) -> str:
    return data()["party_titles"].get(name, name)


def party_kind(kind: str) -> str:
    return data()["party_kinds"].get(kind, kind)


def _compartment_entry(name: str) -> tuple[dict, str] | None:
    texts = data()["compartments"]
    kind, _, instance = name.partition(":")
    entry = texts.get(kind)
    if entry is None:
        return None
    if kind == "access-log" and instance:
        return (entry[instance], "") if instance in entry else None
    return entry, instance


def compartment(name: str) -> str:
    """A compartment, or a compartment kind, named in words."""
    found = _compartment_entry(name)
    if found is None:
        return name
    entry, instance = found
    if not instance and "alone" in entry:
        return entry["alone"]
    return entry["name"].format(instance=instance.replace("-", " "))


def compartment_link(name: str) -> str:
    """A compartment named in words and linked to the glossary, with what it holds as hover."""
    found = _compartment_entry(name)
    if found is None:
        return name
    about = hover(found[0]["about"])
    return f'[{compartment(name)}]({SITE}glossary/#compartment "{about}")'


def needs(requirement: str) -> str:
    """What an attack lacked, as `Attack.missing` words it ("a or b"), in plain words. Anything
    that is not a compartment name, such as a note about missing material, passes through."""
    return " or ".join(compartment(part) for part in requirement.split(" or "))


def claim(metric: str, op: str, threshold: float) -> str:
    """What a claim says of its party, completing the sentence "The party ..."."""
    text = data()["metrics"][metric]
    if op == "<=" and threshold == 0:
        return text["zero"]
    return f"{text['noun']} is {_OPS[op]} {_number(threshold)}"


def verdict(value: str) -> str:
    return data()["verdicts"].get(value, value)


def term(key: str, label: str) -> str:
    """`label` linked to the glossary entry for `key`, with the entry's summary as hover text."""
    entry = data()["terms"][key]
    return f'[{label}]({SITE}glossary/#{entry["anchor"]} "{hover(entry["hover"])}")'


def attack_title(name: str) -> str:
    return data()["attacks"].get(name, {}).get("title", name)


def attack_summary(name: str) -> str:
    return data()["attacks"].get(name, {}).get("summary", "")


def attack_link(name: str) -> str:
    """An attack's title linked to its entry on the attacks page, with its summary as hover
    text, or its id when it has no explanation."""
    if name not in data()["attacks"]:
        return name
    anchor = slug(f"{attack_title(name)} ({name})")
    return f'[{attack_title(name)}]({SITE}attacks/#{anchor} "{hover(attack_summary(name))}")'


def _and(items) -> str:
    items = list(items)
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def attacks_page() -> str:
    """docs/attacks.md: every attack in the catalogue, explained. scripts/attacks-page writes it
    and a test fails when the committed page differs, so the page and the catalogue agree."""
    from .attacks import CATALOGUE

    out = ["# Attacks", "",
           ("Each attack is one way an adversary can correlate what it holds. An attack reads only "
            "a party's compartments, never a running system and never the answer key, and each "
            "first proves on a test setup that it finds a link where one exists and none where "
            "none does. A report lists, for each party, what every attack found. This page is "
            "generated from the catalogue by `scripts/attacks-page`; do not edit it by hand."), ""]
    for attack in sorted(CATALOGUE, key=lambda a: attack_title(a.name).lower()):
        reads = "; and ".join(" or ".join(compartment(k) for k in alternatives)
                              for alternatives in attack.needs)
        out += [f"## {attack_title(attack.name)} ({attack.name})", "",
                attack_summary(attack.name), "",
                (f"It needs {reads}. It tests the {_and(attack.vectors)} "
                 f"[correlation vector{'s' if len(attack.vectors) > 1 else ''}]"
                 "(glossary.md#correlation-vector)."), ""]
    return "\n".join(out)
