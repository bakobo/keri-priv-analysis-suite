"""CESR reading and verification (docs/test-plan.md Part B item 5's verification step)."""

import pytest
from bakobo.errors import BakoboError
from keri.acdc import messaging
from keri.app import habbing
from keri.core import Counter, Salter
from keri.kering import Vrsn_2_0

from keri_priv_analysis import cesr

STAMP = "2026-11-01T00:00:00.000000+00:00"


@pytest.fixture(scope="module")
def issued():
    salt = Salter(raw=b"cesr-test-salt-1").qb64
    with habbing.openHby(name="kpa-cesr-test", temp=True, salt=salt) as hby:
        hab = hby.makeHab(name="issuer", isith="1", icount=1, nsith="1", ncount=1, toad=0)
        rip = messaging.regcept(hab.pre, uuid=Salter(raw=b"r" * 16).qb64, stamp=STAMP)
        upd = messaging.update(rip.said, rip.said, "EAcdcSaidAcdcSaidAcdcSaidAcdcSaidAcdcSaid12",
                               "issued", sn=1, stamp=STAMP)
        hab.interact(data=[{"i": rip.said, "s": "0", "d": rip.said}])
        hab.interact(data=[{"i": rip.said, "s": "1", "d": upd.said}])
        kel = b"".join(bytes(m) for m in hab.db.clonePreIter(pre=hab.pre))
        tel = bytes(Counter.makeGVC(version=Vrsn_2_0)) + rip.raw + upd.raw
        yield hab.pre, kel, tel, rip, upd


def test_messages_reads_kel_and_tel_and_skips_attachments(issued):
    pre, kel, tel, rip, upd = issued
    events = cesr.messages(kel)
    assert [e["t"] for e in events] == ["icp", "ixn", "ixn"]
    assert events[0]["i"] == pre
    tel_events = cesr.messages(tel)
    assert [e["d"] for e in tel_events] == [rip.said, upd.said]


def test_seals_locate_each_anchored_said(issued):
    _pre, kel, _tel, rip, upd = issued
    found = cesr.seals(cesr.messages(kel))
    assert found[rip.said] == (1, 0) and found[upd.said] == (2, 0)


def test_a_corrupt_stream_is_refused_with_a_code(issued):
    _pre, _kel, tel, _rip, _upd = issued
    bad = tel.replace(b'"t":"rip"', b'"t":"rop"')
    with pytest.raises(BakoboError) as raised:
        cesr.messages(bad, name="tel:x")
    assert raised.value.code == "e.input.format.cesr.f"
    assert "tel:x" in str(raised.value)


def test_verify_kel_accepts_a_good_kel_and_rejects_a_tampered_one(issued):
    pre, kel, _tel, _rip, _upd = issued
    assert cesr.verify_kel(kel) == {pre: 2}
    tampered = bytearray(kel)
    i = tampered.index(b'"s":"1"')
    tampered[i:i + 7] = b'"s":"7"'
    assert cesr.verify_kel(bytes(tampered)).get(pre, -1) < 2


def test_verify_tel_reports_sequence_chain_and_anchor_problems(issued):
    _pre, kel, tel, rip, upd = issued
    kel_seals = cesr.seals(cesr.messages(kel))
    events = cesr.messages(tel)
    assert cesr.verify_tel(events, kel_seals) == []
    # The update repeated: wrong sequence number, and off its prior.
    assert len(cesr.verify_tel(events + events[1:], kel_seals)) == 2
    assert cesr.verify_tel(events, {}) == [
        f"event {rip.said} is not sealed in the issuer's KEL",
        f"event {upd.said} is not sealed in the issuer's KEL",
    ]
    ownerless = [{"t": "ixn", "d": "E1", "s": "1", "a": ["not a seal"]}]
    assert cesr.seals(ownerless) == {}


def _v1_registry():
    from keri.kering import Vrsn_1_0
    from keri.vdr import eventing
    issuer = "EPC5K6miQ2syaqWg5IOhk7JqTJRSGI95qDIpJOsNZnps"
    from keri.core import Diger
    a, b = Diger(ser=b"credential a").qb64, Diger(ser=b"credential b").qb64
    vcp = eventing.incept(issuer, baks=[], toad=0, cnfg=["NB"], nonce=Salter(raw=b"v" * 16).qb64,
                          version=Vrsn_1_0)
    vrt = eventing.rotate(vcp.pre, vcp.said, sn=1, baks=[], version=Vrsn_1_0)
    iss_a = eventing.issue(a, vcp.pre, dt=STAMP, version=Vrsn_1_0)
    rev_a = eventing.revoke(a, vcp.pre, iss_a.said, dt=STAMP, version=Vrsn_1_0)
    bis_b = eventing.backerIssue(b, vcp.pre, 1, vrt.said, dt=STAMP, version=Vrsn_1_0)
    return vcp, vrt, iss_a, rev_a, bis_b


def test_v1_tel_events_read_as_registry_and_credential_events():
    vcp, vrt, iss_a, rev_a, bis_b = _v1_registry()
    stream = b"-VAm" + vcp.raw + b"-GAB" + vrt.raw + iss_a.raw + rev_a.raw + bis_b.raw
    events = cesr.messages(stream)
    kinds = [cesr.tel_event(e) for e in events]
    assert [k["kind"] for k in kinds] == ["inception", "update", "update", "update", "update"]
    assert {k["registry"] for k in kinds} == {vcp.pre}
    assert kinds[0]["issuer"] == "EPC5K6miQ2syaqWg5IOhk7JqTJRSGI95qDIpJOsNZnps"
    assert [k["credential"] for k in kinds[2:]] == [iss_a.sad["i"], iss_a.sad["i"],
                                                    bis_b.sad["i"]]
    sealed = {e["d"]: (1, 0) for e in events}
    assert cesr.verify_tel(events, sealed) == []
    # A credential's revocation without its issuance starts its chain at the wrong number.
    assert cesr.verify_tel([events[0], events[3]], sealed) == [
        f"event {rev_a.said} has sequence number 1, expected 0"]


def test_bytes_that_are_neither_messages_nor_attachments_are_refused():
    assert cesr.messages(b"") == []
    assert cesr.messages(bytes(Counter.makeGVC(version=Vrsn_2_0))) == []
    with pytest.raises(BakoboError) as raised:
        cesr.messages(b"hello, world")
    assert raised.value.code == "e.input.format.cesr.f"


def test_first_seen_reads_replay_times_and_skips_messages_without_them(issued):
    _pre, kel, tel, _rip, _upd = issued
    times = cesr.first_seen(kel)
    assert len(times) == 3
    assert cesr.first_seen(tel) == {}


def test_garbage_around_a_message_is_refused(issued):
    _pre, _kel, _tel, rip, upd = issued
    for bad in (rip.raw + b"GARBAGE!", b"GARBAGE!" + rip.raw, rip.raw + b" " + upd.raw):
        with pytest.raises(BakoboError) as raised:
            cesr.messages(bad)
        assert raised.value.code == "e.input.format.cesr.f"


def test_seals_skip_messages_that_are_not_key_events_and_tel_events_must_be_tel():
    assert cesr.seals([{"t": "exn", "a": [{"d": "Ex"}]}]) == {}
    with pytest.raises(BakoboError) as raised:
        cesr.tel_event({"t": "ixn", "d": "Eixn", "i": "Epre", "s": "1"})
    assert raised.value.code == "e.input.format.stream-shape.f"
