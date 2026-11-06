"""The contract suite catches each way an adapter can break the contract."""

import dataclasses

from worlds import world

from keri_priv_analysis import contract
from keri_priv_analysis.model import Compartment, CompartmentSet, LogLine


def _replace(cs, name, **changes):
    return CompartmentSet(dataclasses.replace(c, **changes) if c.name == name else c for c in cs)


def test_an_omitted_or_extra_compartment_is_reported():
    s, _, cs, _truth, _k = world(count=6, copies=3)
    fewer = CompartmentSet(c for c in cs if c.name != "orchestrator")
    assert contract.compartments_accounted(s, fewer) == [
        "compartment orchestrator is missing: report it absent or not measured, never omit it"]
    more = CompartmentSet([*cs, Compartment(name="verifier:stranger", status="absent")])
    assert contract.compartments_accounted(s, more) == [
        "compartment verifier:stranger is not one this scenario has"]


def test_wrong_presentation_counts_duplicates_and_strays_are_reported():
    s, population, cs, truth, _k = world(count=6, copies=3)
    store = cs["verifier:pharmacy"]
    dropped = _replace(cs, "verifier:pharmacy", presentations=store.presentations[1:])
    problems = contract.presentation_counts(s, dropped, truth, population)
    assert "the presentations exported and those in ground truth differ" in problems
    assert any("but the scenario specifies 1" in p for p in problems)
    doubled = _replace(cs, "verifier:pharmacy",
                       presentations=store.presentations + store.presentations[:1])
    assert any("appears 2 times"
               in p for p in contract.presentation_counts(s, doubled, truth, population))


def test_an_identifier_the_adapter_never_issued_is_reported():
    _s, _, cs, truth, k = world(count=6, copies=3)
    stray = "E" + "x" * 43
    bad = _replace(cs, "access-log:mailbox", logs=[LogLine(1.0, "10.0.0.1", f"PUT {stray}")])
    assert contract.identifiers_issued(bad, truth, k) == [
        (f"compartment access-log:mailbox names 1 identifiers the adapter did not issue, "
        f"such as {stray}")]
    assert contract.identifiers("a EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA b") == [
        "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
    assert contract.identifiers("EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == []  # 45 long


def test_a_kel_that_does_not_verify_or_a_tel_off_its_anchor_is_reported():
    _s, _, cs, _truth, _k = world(count=6, copies=3)
    streams = dict(cs["public"].streams)
    kel_name = next(n for n in streams if n.startswith("kel:"))
    events = streams[kel_name]
    cut = events.index(b'{"v":"KERI', events.index(b'"t":"ixn"'))
    # Drop one interaction event: the rest no longer chain, and its TEL loses its anchor.
    nxt = events.index(b'{"v":"KERI', cut + 1)
    streams[kel_name] = events[:cut] + events[nxt:]
    problems = contract.streams_verify(_replace(cs, "public", streams=streams))
    assert any(p.startswith(f"{kel_name} does not verify") for p in problems)
    assert any("is not sealed in the issuer's KEL" in p for p in problems)


def test_check_combines_every_check():
    s, population, cs, truth, k = world(count=6, copies=3)
    assert contract.check(s, cs, truth, k, population) == []
    fewer = CompartmentSet(c for c in cs if c.name != "orchestrator")
    assert len(contract.check(s, fewer, truth, k, population)) == 1


def test_presentations_without_their_credential_or_without_a_public_record_are_reported():
    _s, _, cs, _truth, _k = world(count=6, copies=3)
    store = cs["verifier:pharmacy"]
    empty = _replace(cs, "verifier:pharmacy", presentations=[
        dataclasses.replace(p, raw=b"") for p in store.presentations])
    problems = contract.streams_verify(empty)
    assert any("does not carry credential" in p for p in problems)
    bare = _replace(cs, "public", streams={})
    assert sum("the public record has no" in p for p in contract.streams_verify(bare)) == 2


def test_a_holder_kel_that_does_not_verify_is_reported():
    assert contract.streams_verify(world(count=6, copies=3, holder_aids="delegated")[2]) == []
    _s, _, cs, _truth, _k = world(count=6, copies=3)
    store = cs["verifier:pharmacy"]
    name, kel = next(iter(store.streams.items()))
    # Flip one character of the last signature: still CESR, no longer a valid signature.
    last = kel[-2:-1]
    forged = kel[:-2] + (b"A" if last != b"A" else b"B") + kel[-1:]
    broken = _replace(cs, "verifier:pharmacy", streams={**store.streams, name: forged})
    assert any(p.startswith(f"verifier:pharmacy {name} does not verify")
               for p in contract.streams_verify(broken))
    misnamed = _replace(cs, "verifier:pharmacy", streams={"kel:E" + "Q" * 43: kel})
    assert any("holds no event of" in p for p in contract.streams_verify(misnamed))


def test_a_record_with_no_presentations_needs_no_kel_and_other_verifier_streams_are_ignored():
    _s, _, _cs, _truth, _k = world(count=6, copies=3)
    nothing_presented = CompartmentSet([Compartment(name="public", status="present"),
                                        Compartment(name="verifier:v", status="present",
                                                    streams={"note:x": b"not a kel"})])
    assert contract.streams_verify(nothing_presented) == []


def test_a_tel_must_be_sealed_in_its_own_issuers_kel():
    _s, _, cs, _truth, _k = world(count=6, copies=3, homes=2)
    streams = dict(cs["public"].streams)
    kels = [n for n in streams if n.startswith("kel:")]
    # Swap which name each issuer's KEL is filed under: every TEL is now checked against the
    # other issuer's seals, and none of its events is found there.
    swapped = {**streams, kels[0]: streams[kels[1]], kels[1]: streams[kels[0]]}
    problems = contract.streams_verify(_replace(cs, "public", streams=swapped))
    assert any("is not sealed in the issuer's KEL" in p for p in problems)
    tel = next(n for n in streams if n.startswith("tel:"))
    from keri_priv_analysis import cesr as c
    headless = streams[tel][streams[tel].index(b'{"v":"ACDC', 30):]
    assert c.messages(headless)[0]["t"] == "upd"
    problems = contract.streams_verify(_replace(cs, "public", streams={**streams, tel: headless}))
    assert f"{tel} does not name exactly one issuer" in problems


def test_a_presentation_in_the_wrong_domain_or_disclosing_other_attributes_is_reported():
    s, population, cs, truth, _k = world(count=6, copies=3)
    store = cs["verifier:pharmacy"]
    moved = _replace(cs, "verifier:pharmacy", presentations=[
        dataclasses.replace(store.presentations[0], domain="alcohol"),
        *store.presentations[1:]])
    problems = contract.presentation_counts(s, moved, truth, population)
    assert any("which no plan names" in p for p in problems)
    stripped = _replace(cs, "verifier:pharmacy", presentations=[
        dataclasses.replace(store.presentations[0], disclosed={}), *store.presentations[1:]])
    assert any("which no plan names" in p
               for p in contract.presentation_counts(s, stripped, truth, population))


def test_two_plans_for_one_verifier_and_domain_are_each_held_to_their_own_disclosures():
    s, population, cs, truth, _k = world(count=6, copies=4)
    plans = list(s.presentations)
    narrow = dataclasses.replace(plans[1], disclose=("county",), per_citizen=1)
    wide = dataclasses.replace(plans[1], per_citizen=1)
    two = dataclasses.replace(s, presentations=(plans[0], narrow, wide))
    store = cs["verifier:pharmacy"]
    by_citizen = {}
    for p in store.presentations:
        by_citizen.setdefault(truth.presentations[p.handle], []).append(p)
    # Each citizen's two pharmacy presentations: one disclosing county alone, one both attributes.
    fitted = [dataclasses.replace(ps[0], disclosed={"county": ps[0].disclosed["county"]})
              for ps in by_citizen.values()] + [ps[1] for ps in by_citizen.values()]
    good = _replace(cs, "verifier:pharmacy", presentations=fitted)
    assert contract.presentation_counts(two, good, truth, population) == []
    # Over-disclosing on every presentation is not the union of the plans: it is refused.
    assert contract.presentation_counts(two, cs, truth, population) != []


def test_a_disclosed_value_the_citizen_does_not_hold_is_reported():
    s, population, cs, truth, _k = world(count=6, copies=3)
    store = cs["verifier:pharmacy"]
    first = store.presentations[0]
    forged = {a: v + "-forged" for a, v in first.disclosed.items()}
    bad = _replace(cs, "verifier:pharmacy", presentations=[
        dataclasses.replace(first, disclosed=forged), *store.presentations[1:]])
    assert contract.presentation_counts(s, bad, truth, population) == [
        (f"presentation {first.handle} discloses {sorted(forged)} with values its citizen does "
        "not hold")]
    stranger = _replace(cs, "verifier:pharmacy", presentations=[
        dataclasses.replace(first, handle="stranger"), *store.presentations[1:]])
    assert "the presentations exported and those in ground truth differ" in (
        contract.presentation_counts(s, stranger, truth, population))  # no citizen to compare


def test_a_presentation_outside_its_plans_window_is_reported():
    s, population, cs, truth, _k = world(count=6, copies=3)
    store = cs["verifier:pharmacy"]
    first = store.presentations[0]
    late = dataclasses.replace(first, time=max(p.end for p in s.presentations) + 1.0)
    bad = _replace(cs, "verifier:pharmacy", presentations=[late, *store.presentations[1:]])
    plan = next(q for q in s.presentations if q.verifier == first.verifier)
    assert contract.presentation_counts(s, bad, truth, population) == [
        (f"presentation {first.handle} at {late.time} falls in no window of a plan for "
         f"{first.verifier} in {first.domain} disclosing {sorted(first.disclosed)}"),
        (f"citizen {truth.presentations[first.handle]} made 0 presentations to pharmacy in "
         f"pharmacy disclosing {sorted(plan.disclose)} between {plan.start} and {plan.end}, but "
         "the scenario specifies 1")]


def test_two_windows_for_the_same_disclosures_are_each_counted():
    s, population, cs, truth, _k = world(count=6, copies=3)
    store = cs["verifier:pharmacy"]
    first = store.presentations[0]
    plan = next(q for q in s.presentations if q.verifier == first.verifier)
    later = dataclasses.replace(plan, start=plan.end + 10.0, end=plan.end + 20.0)
    two = dataclasses.replace(s, presentations=(*s.presentations, later))
    extra = dataclasses.replace(first, handle="extra", time=first.time)
    both_early = _replace(cs, "verifier:pharmacy", presentations=[*store.presentations, extra])
    t = dataclasses.replace(truth, presentations={**truth.presentations,
                                                  "extra": truth.presentations[first.handle]})
    problems = contract.presentation_counts(two, both_early, t, population)
    assert any(p.startswith(f"citizen {t.presentations['extra']} made 2 presentations")
               for p in problems)
    assert sum("made 0 presentations" in p for p in problems) == len(truth.citizen_rows)


def test_a_presentation_mapped_to_no_simulated_citizen_is_reported():
    s, population, cs, truth, _k = world(count=6, copies=3)
    first = cs["verifier:pharmacy"].presentations[0]
    for bad in (-1, len(truth.citizen_rows), "0", True, None):
        t = dataclasses.replace(truth, presentations={**truth.presentations, first.handle: bad})
        assert (f"presentation {first.handle} belongs to citizen {bad!r}, which is not a "
                "simulated citizen") in contract.presentation_counts(s, cs, t, population)


def test_a_citizen_given_no_row_of_the_population_is_reported():
    s, population, cs, truth, _k = world(count=6, copies=3)
    for bad in (-1, population.size, 1.0, True):
        t = dataclasses.replace(truth, citizen_rows=[bad, *truth.citizen_rows[1:]])
        assert (f"citizen 0 is given population row {bad!r}, which is not a row of the "
                "population table") in contract.presentation_counts(s, cs, t, population)


def test_a_result_with_the_wrong_number_of_citizens_is_reported():
    s, population, cs, truth, _k = world(count=6, copies=3)
    for rows in ([], truth.citizen_rows[:-1]):
        t = dataclasses.replace(truth, citizen_rows=rows)
        assert (f"ground truth has {len(rows)} citizens, but the scenario specifies 6"
                in contract.presentation_counts(s, cs, t, population))


def test_a_kel_stream_holding_other_messages_is_reported():
    _s, _, cs, _truth, _k = world(count=6, copies=3)
    streams = dict(cs["public"].streams)
    kel = next(n for n in streams if n.startswith("kel:"))
    tel = next(n for n in streams if n.startswith("tel:"))
    mixed = _replace(cs, "public", streams={**streams, kel: streams[kel] + streams[tel]})
    assert any("holds messages that are not key events" in p
               for p in contract.streams_verify(mixed))
