from types import SimpleNamespace

import pytest

from kpa_keria_stack.exporting import Owners, _agents_of

A = "E" + "a" * 43
B = "E" + "b" * 43
C = "E" + "c" * 43
D = "E" + "d" * 43
ISSUER = "E" + "i" * 43
HOLDER0, HOLDER1 = "E" + "0" * 43, "E" + "1" * 43


class Items:
    def __init__(self, items):
        self.items = items

    def getItemIter(self):
        return iter(self.items)


def sad(**fields):
    return SimpleNamespace(sad=fields)


class FakeStore:
    def __init__(self, kels, exns=(), rpys=(), creds=(), ends=()):
        self._kels = kels
        self.db = SimpleNamespace(exns=Items(exns), rpys=Items(rpys))
        self.reger = SimpleNamespace(creds=Items(creds))
        self._ends = list(ends)

    def identifiers(self):
        return self._kels

    def message(self, said):
        return f"{said} {ISSUER}"

    def credential(self, said):
        return f"{said} {ISSUER}"

    def tel(self, said):
        return f"{said} {D}"

    def end_roles(self):
        return self._ends


def test_owners_keep_the_states_identifiers_and_give_the_rest_to_citizens():
    owners = Owners({HOLDER0: 0, HOLDER1: 1}, nobody=[C])
    store = FakeStore(
        kels={ISSUER: {ISSUER}, HOLDER0: {HOLDER0, A}},
        exns=[((B,), sad(i=ISSUER, rp=HOLDER0))],
        rpys=[((("E" + "r" * 43),), sad(a={"eid": HOLDER1})),
              ((("E" + "s" * 43),), sad(a={"cid": "unknown"})),
              ((("E" + "t" * 43),), sad())],
        creds=[((D,), sad(a={"i": HOLDER1}))])
    owners.read(store)
    citizen, nobody = owners.resolve()
    assert citizen == {HOLDER0: 0, A: 0, B: 0, "E" + "r" * 43: 1, D: 1}
    assert nobody == sorted({ISSUER, C, "E" + "s" * 43, "E" + "t" * 43})


def test_owners_refuse_an_identifier_two_citizens_claim():
    owners = Owners({HOLDER0: 0, HOLDER1: 1})
    owners.read(FakeStore(kels={HOLDER0: {A}, HOLDER1: {A}}))
    with pytest.raises(ValueError, match="claimed by citizens 0 and 1"):
        owners.resolve()


def test_agents_of_reads_holder_agent_end_roles():
    store = FakeStore({}, ends=[{"aid": HOLDER0, "role": "agent", "eid": A},
                                {"aid": HOLDER1, "role": "controller", "eid": B},
                                {"aid": ISSUER, "role": "agent", "eid": C}])
    assert _agents_of(store, {HOLDER0: 0, HOLDER1: 1}) == {HOLDER0: A}
