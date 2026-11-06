"""The issuer-AID bucket (F8, F-J180): which home signed adds about log2 N bits, without a join."""

from __future__ import annotations

from ..model import CompartmentSet, Knowledge, Observation
from ..population import HOME


def issuer_bucket(cs: CompartmentSet, k: Knowledge) -> list[Observation]:
    return [Observation("p:" + p.handle, HOME, k.issuers[p.issuer], "issuer-aid-bucket")
            for p in cs.presentations() if p.issuer in k.issuers]
