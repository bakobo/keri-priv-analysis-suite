"""Read and verify the CESR streams a compartment holds, with keripy.

Attacks read messages' fields; they never verify. The adapter contract suite verifies: a KEL by
replaying it into a fresh keripy Kevery, and a TEL by checking each event's chain to its prior and
the seal anchoring it in the issuer's KEL.
"""

from __future__ import annotations

import re

from keri.core import Dater, eventing, parsing, serdering
from keri.db import basing
from keri.kering import KeriError, Vrsn_1_0, Vrsn_2_0

from . import errors

_START = b'{"v":"'
_DATER = b"1AAG"
KEL_ILKS = ("icp", "rot", "ixn", "dip", "drt")
# Text-domain CESR between messages: counters, attachments and genus codes, all base64url.
_FRAMING = re.compile(rb"[A-Za-z0-9_-]*")


def first_seen(stream: bytes, name: str = "stream") -> dict[str, float]:
    """For each message in a KEL replay that carries a first-seen couple, its first-seen time.

    keripy replays a KEL with each event's first-seen ordinal and datetime attached; the time is
    the replaying node's own clock, untouched by any granularity applied to TEL `dt` fields.
    """
    out = {}
    for sad, attachments in framed(stream, name):
        at = attachments.find(_DATER)
        if at >= 0:
            out[sad["d"]] = Dater(qb64b=attachments[at:at + 36]).datetime.timestamp()
    return out


def messages(stream: bytes, name: str = "stream") -> list[dict]:
    """The field maps of every KERI and ACDC message in the stream, in order, v1 or v2."""
    return [sad for sad, _ in framed(stream, name)]


def framed(stream: bytes, name: str = "stream") -> list[tuple[dict, bytes]]:
    """Every KERI and ACDC message in the stream with the attachment bytes that follow it.

    Between messages it skips to the next message's opening, which in the text domain is the only
    place a brace can appear: attachments, counters and genus codes are all base64url. A
    message's SAID is verified as it is read, because keripy's serders refuse one whose digest
    does not match.
    """
    ims = bytes(stream)
    out = []
    at = ims.find(_START)
    if not _FRAMING.fullmatch(ims[:at] if at >= 0 else ims):
        raise errors.CESR_FORMAT(name=name, reason="bytes before its first message are not CESR "
                                 "counters or attachments")
    try:
        while at >= 0:
            head = ims[at:at + 24]
            kind = serdering.SerderKERI if b'"KERI' in head else serdering.SerderACDC
            serder = kind(raw=ims[at:])
            following = ims.find(_START, at + serder.size)
            attachments = ims[at + serder.size:following if following >= 0 else None]
            if not _FRAMING.fullmatch(attachments):
                raise ValueError(f"bytes after message {serder.said} are not CESR attachments")
            out.append((serder.sad, attachments))
            at = following
    except (KeriError, ValueError, KeyError, IndexError, TypeError) as exc:
        raise errors.CESR_FORMAT(name=name, reason=f"{type(exc).__name__}: {exc}") from None
    return out


def seals(kel: list[dict]) -> dict[str, tuple[int, int]]:
    """For each sealed SAID in an issuer's KEL, the KEL sequence number and the seal's position."""
    out = {}
    for event in kel:
        if event.get("t") not in KEL_ILKS:
            continue
        for position, seal in enumerate(event.get("a", [])):
            if isinstance(seal, dict) and "d" in seal:
                out[seal["d"]] = (int(event["s"], 16), position)
    return out


def verify_kel(stream: bytes) -> dict[str, int]:
    """Replay a KEL into a fresh keripy Kevery; return each accepted prefix's last sequence number.

    The stream is parsed as KERI v2 and then as v1, so either generation verifies.
    """
    accepted = {}
    for version in (Vrsn_2_0, Vrsn_1_0):
        with basing.openDB(name="kpa-verify", temp=True) as db:
            kevery = eventing.Kevery(db=db, lax=False, local=False)
            parsing.Parser(kvy=kevery, version=version).parse(ims=bytearray(stream))
            for pre, kever in kevery.kevers.items():
                accepted[pre] = max(accepted.get(pre, -1), kever.sn)
    return accepted


def tel_event(event: dict) -> dict:
    """A TEL event of either generation, as the fields attacks use.

    kind is "inception" for a registry's inception (`rip`, `vcp`) and "update" otherwise. chain
    names the TEL the event extends: the registry for v2 and for a v1 registry event, the
    credential for a v1 credential event, whose own TEL is separate from its registry's.
    """
    t = event["t"]
    if t == "rip":
        return {"kind": "inception", "registry": event["d"], "credential": None,
                "issuer": event["i"], "chain": event["d"], "sn": int(event["n"], 16)}
    if t in ("upd", "bup"):
        return {"kind": "update", "registry": event["rd"], "credential": event.get("td"),
                "issuer": None, "chain": event["rd"], "sn": int(event["n"], 16)}
    if t in ("vcp", "vrt"):
        return {"kind": "inception" if t == "vcp" else "update", "registry": event["i"],
                "credential": None, "issuer": event.get("ii"), "chain": event["i"],
                "sn": int(event["s"], 16)}
    if t not in ("iss", "rev", "bis", "brv"):
        raise errors.STREAM_SHAPE(name=event.get("d", "a TEL"),
                                  reason=f"a {t!r} message is not a TEL event")
    registry = event["ra"]["i"] if "ra" in event else event["ri"]
    return {"kind": "update", "registry": registry, "credential": event["i"], "issuer": None,
            "chain": event["i"], "sn": int(event["s"], 16)}


def verify_tel(tel: list[dict], kel_seals: dict[str, tuple[int, int]]) -> list[str]:
    """Problems with a TEL stream: an event out of sequence, off its prior, or not sealed in a KEL.

    A stream may hold several chains, as a v1 registry's stream holds each credential's own TEL;
    each chain is checked on its own.
    """
    problems = []
    prior: dict[str, tuple[str, int]] = {}
    for event in tel:
        e = tel_event(event)
        n = e["sn"]
        want = 0 if e["chain"] not in prior else prior[e["chain"]][1] + 1
        if n != want:
            problems.append(f"event {event['d']} has sequence number {n:x}, expected {want:x}")
        if e["chain"] in prior and event.get("p") != prior[e["chain"]][0]:
            problems.append(f"event {event['d']} does not chain to {prior[e['chain']][0]}")
        if event["d"] not in kel_seals:
            problems.append(f"event {event['d']} is not sealed in the issuer's KEL")
        prior[e["chain"]] = (event["d"], n)
    return problems
