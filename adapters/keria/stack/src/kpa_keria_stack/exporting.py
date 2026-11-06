"""Read what each KERIA host stored, after it stopped, as a party who obtained its disk would.

Each agent's stores are the LMDB databases KERIA keeps per controller: the Baser (KELs, key state,
end roles, exchange messages) and the Reger (registries, TELs, credentials). They are opened read
only with the keripy KERIA itself uses, and turned into the shapes the suite reads: CESR streams in
the text domain, rows of named fields, and raw log lines.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

from keri.app import signing as app_signing
from keri.core import (
    eventing,  # noqa: F401  (keri.db.basing must import after keri.core.eventing)
    serdering,
)
from keri.db import basing
from keri.peer import exchanging
from keri.vdr import viring

# The suite's own test for a token shaped like a 44-character qb64 identifier.
IDENTIFIER = re.compile(r"(?<![A-Za-z0-9_-])[A-Z][A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")


class Store:
    """One agent's databases on a stopped host, opened read only."""

    def __init__(self, host, controller: str):
        head = str(host.data)
        self.db = basing.Baser(name=controller, headDirPath=head, reopen=True, readonly=True)
        self.reger = viring.Reger(name=f"agent-{controller}", headDirPath=head, reopen=True,
                                  readonly=True)

    def close(self) -> None:
        self.reger.close()
        self.db.close()

    def kel(self, pre: str) -> str:
        return b"".join(bytes(m) for m in self.db.clonePreIter(pre=pre)).decode()

    def tel(self, pre: str) -> str:
        return b"".join(bytes(m) for m in self.reger.clonePreIter(pre=pre)).decode()

    def prefixes(self) -> list[str]:
        return sorted({keys[0] for keys, _ in self.db.states.getItemIter()})

    def credential(self, said: str) -> str:
        creder, prefixer, seqner, saider = self.reger.cloneCred(said)
        return bytes(app_signing.serialize(creder, prefixer, seqner, saider)).decode()

    def message(self, said: str) -> str:
        """An exchange message as it was received: the exn, its signatures and pathed
        attachments."""
        hby = SimpleNamespace(db=self.db, kevers=self.db.kevers)
        return bytes(exchanging.serializeMessage(hby, said)).decode()

    def credentials(self) -> list[dict]:
        out = []
        for (said,), creder in self.reger.creds.getItemIter():
            sad = creder.sad
            row = {"said": said, "registry": sad.get("ri", ""), "issuer": sad["i"],
                   "holder": sad["a"].get("i", ""), "schema": sad["s"],
                   "dt": sad["a"].get("dt", "")}
            row |= {f"a.{k}": str(v) for k, v in sad["a"].items() if k not in ("d", "i", "dt")}
            out.append(row)
        return out

    def exchanges(self) -> list[dict]:
        return [{"said": said, "route": exn.sad["r"], "sender": exn.sad["i"],
                 "recipient": exn.sad.get("rp", ""), "dt": exn.sad.get("dt", "")}
                for (said,), exn in self.db.exns.getItemIter()]

    def end_roles(self) -> list[dict]:
        return [{"aid": aid, "role": role, "eid": eid}
                for (aid, role, eid), end in self.db.ends.getItemIter() if end.allowed]

    def identifiers(self) -> dict[str, set[str]]:
        """The identifiers each KEL this agent holds makes for itself, by the AID whose KEL it
        is: its prefix, event SAIDs, keys, digests, witnesses and delegator. What its events seal
        is left out, since an issuer's KEL seals its citizens' credentials."""
        out = {}
        for pre in self.prefixes():
            ids = set()
            for msg in self.db.clonePreIter(pre=pre):
                sad = dict(serdering.SerderKERI(raw=bytes(msg)).sad)
                sad.pop("a", None)
                ids |= set(IDENTIFIER.findall(json.dumps(sad)))
            out[pre] = ids
        return out


def _agents_of(store: Store, holders: dict[str, int]) -> dict[str, str]:
    """Holder AID -> the agent AID its agent end role names, from a store's end-role records.
    KERIA has no management AID; the agent the holder authorised is what the home can key a
    citizen by, since one agent serves all of a citizen's AIDs."""
    return {row["aid"]: row["eid"] for row in store.end_roles()
            if row["role"] == "agent" and row["aid"] in holders}


class Owners:
    """Whose each identifier is: a citizen's, or nobody's (the State's, a verifier's, an agency's).

    An identifier in the KEL of an AID nobody but the State or a verifier controls is nobody's, and
    stays so even when it also appears in a citizen's credential or messages, as an issuer's AID
    and registry do. Every other identifier in a citizen's KELs, credentials and messages is that
    citizen's.
    """

    def __init__(self, controlled: dict[str, int], nobody=()):
        self.controlled = controlled
        self.nobody: set[str] = set(nobody)
        self.citizen: dict[str, int] = {}
        self.pending: list[tuple[set[str], int]] = []

    def read(self, store: Store) -> None:
        for pre, ids in store.identifiers().items():
            self._give(ids, self.controlled.get(pre))
        for said, exn in ((keys[0], e) for keys, e in store.db.exns.getItemIter()):
            who = self.controlled.get(exn.sad["i"], self.controlled.get(exn.sad.get("rp", "")))
            self._give({said} | set(IDENTIFIER.findall(store.message(said))), who)
        for (said,), rpy in store.db.rpys.getItemIter():
            # An end-role or location reply is the authorising AID's (cid), or the endpoint's.
            a = rpy.sad.get("a", {})
            who = self.controlled.get(a.get("cid", ""), self.controlled.get(a.get("eid", "")))
            self._give({said}, who)
        for (said,), creder in store.reger.creds.getItemIter():
            who = self.controlled.get(creder.sad["a"].get("i", ""))
            self._give(set(IDENTIFIER.findall(store.credential(said) + store.tel(said))), who)

    def _give(self, ids: set[str], who: int | None) -> None:
        if who is None:
            self.nobody |= ids
        else:
            self.pending.append((ids, who))

    def resolve(self) -> tuple[dict[str, int], list[str]]:
        """Citizen identifiers, and nobody's; an identifier two citizens claim is a bug here."""
        for ids, who in self.pending:
            for i in ids - self.nobody:
                if self.citizen.setdefault(i, who) != who:
                    raise ValueError(f"identifier {i} is claimed by citizens "
                                     f"{self.citizen[i]} and {who}")
        return self.citizen, sorted(self.nobody - set(self.citizen))


def export(world, hosts) -> dict:
    holders = {h: c for c, cz in enumerate(world.citizens) for h in cz.holders}
    controlled = dict(holders)
    for c, cz in enumerate(world.citizens):
        controlled[cz.party.agent] = c
        controlled[cz.party.controller] = c
    owners = Owners(controlled, [world.schema] + [i["registry"] for i in world.issuers])
    homes, public, timeline = [], {}, world.timeline
    by_home = {}
    for cred in world.credentials:
        by_home.setdefault(cred["home"], []).append(cred)
    for h, issuer in enumerate(world.issuers):
        store = Store(hosts[f"home-{h}"], issuer["party"].controller)
        try:
            public[f"kel:{issuer['aid']}"] = store.kel(issuer["aid"])
            tel = store.tel(issuer["registry"])
            tel += "".join(store.tel(cred["said"]) for cred in by_home.get(h, []))
            public[f"tel:{issuer['registry']}"] = tel
            agents = _agents_of(store, holders)
            rows = []
            for row in store.credentials():
                rows.append({**row, "management": agents.get(row["holder"], "")})
            homes.append({"records": {"credentials": rows, "exchanges": store.exchanges(),
                                      "end-roles": store.end_roles()},
                          "logs": hosts[f"home-{h}"].log(),
                          "address": hosts[f"home-{h}"].address})
            owners.read(store)
        finally:
            store.close()
    verifiers = {}
    raws = {}
    for v, verifier in world.verifiers.items():
        store = Store(hosts[f"verifier-{v}"], verifier["party"].controller)
        try:
            mine = [p for p in world.presented if p["verifier"] == v]
            kels = {p["holder"]: store.kel(p["holder"]) for p in mine}
            for p in mine:
                raws[p["grant"]] = store.message(p["grant"]) + store.credential(p["said"])
            verifiers[v] = {"kels": kels, "records": {"credentials": store.credentials(),
                                                     "exchanges": store.exchanges(),
                                                     "end-roles": store.end_roles()},
                            "logs": hosts[f"verifier-{v}"].log(),
                            "address": hosts[f"verifier-{v}"].address}
            owners.read(store)
        finally:
            store.close()
    wallet_rows, held = [], []
    for c, cz in enumerate(world.citizens):
        store = Store(hosts["wallet"], cz.party.controller)
        try:
            wallet_rows += [{"agent": cz.party.agent, "controller": cz.party.controller,
                             "holder": h} for h in cz.holders]
            held += store.credentials()
            owners.read(store)
        finally:
            store.close()
    artifacts, nobody = owners.resolve()
    return {
        "issuers": [{"aid": i["aid"], "registry": i["registry"], "agent": i["party"].agent,
                     "controller": i["party"].controller} for i in world.issuers],
        "verifiers": {v: {"aid": x["aid"], "agent": x["party"].agent,
                          "controller": x["party"].controller, **verifiers[v]}
                      for v, x in world.verifiers.items()},
        "citizens": [{"agent": cz.party.agent, "controller": cz.party.controller,
                      "holders": cz.holders} for cz in world.citizens],
        "credentials": world.credentials,
        "presentations": [{**p, "raw": raws[p["grant"]]} for p in world.presented],
        "public": public,
        "homes": homes,
        "wallet": {"records": {"agents": wallet_rows, "credentials": held},
                   "logs": hosts["wallet"].log(), "address": hosts["wallet"].address},
        "timeline": timeline,
        "artifacts": artifacts,
        "nobody": nobody,
    }

