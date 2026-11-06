from datetime import datetime

import pytest
import requests
from bakobo.errors import BakoboError
from requests import HTTPError

from kpa_keria_stack import __main__ as entry
from kpa_keria_stack import driver


def test_secret_is_fixed_by_seed_and_parts():
    s = driver.secret(1, "home", 0)
    assert len(s) == 21 and set(s) <= set(driver.ALPHABET)
    assert s == driver.secret(1, "home", 0) != driver.secret(2, "home", 0)
    assert driver.secret(1, "home", 1) != s


def test_alias_says_nothing_of_its_citizen():
    a = driver.alias(1, 3, 0)
    assert a.startswith("aid-") and len(a) == 16 and "3" not in a[:4]
    assert a == driver.alias(1, 3, 0) != driver.alias(1, 3, 1)


def test_stamp_is_now_or_truncated_now():
    exact = datetime.fromisoformat(driver.stamp(0.0))
    assert abs(exact.timestamp() - datetime.now().timestamp()) < 5
    coarse = datetime.fromisoformat(driver.stamp(3600.0))
    assert coarse.timestamp() % 3600 == 0 and coarse.microsecond == 0


def test_until_returns_retries_and_gives_up(monkeypatch):
    monkeypatch.setattr(driver, "POLL", 0.0)
    assert driver.until(lambda: 5, "five") == 5
    answers = iter([HTTPError("not yet"), None, 7])

    def fetch():
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    assert driver.until(fetch, "seven") == 7
    with pytest.raises(BakoboError) as exc:
        driver.until(lambda: None, "nothing", timeout=0.01)
    assert exc.value.code == "e.env.keria.wait.r"


def test_check_plan_names_a_missing_key():
    plan = dict.fromkeys(driver.PLAN_KEYS)
    driver.check_plan(plan)
    del plan["issuance"]
    with pytest.raises(BakoboError) as exc:
        driver.check_plan(plan)
    assert exc.value.code == "e.input.format.keria-plan.f" and "issuance" in str(exc.value)


def test_hosts_for_gives_each_boundary_its_own_agency(tmp_path):
    hosts = driver.hosts_for({"homes": 2, "verifiers": ["a", "b"]}, tmp_path, ["u"])
    assert list(hosts) == ["home-0", "home-1", "wallet", "verifier-a", "verifier-b"]
    assert len({h.admin for h in hosts.values()}) == 5


class FakeClient:
    fails = 0
    made = 0

    def __init__(self, **kwargs):
        FakeClient.made += 1
        self.agent = type("A", (), {"pre": "agent"})()
        self.ctrl = type("C", (), {"pre": "ctrl"})()

    def boot(self):
        if FakeClient.made <= FakeClient.fails:
            raise requests.ConnectionError("reset")

    def connect(self):
        pass


def test_party_retries_a_boot_the_agency_is_not_ready_for(monkeypatch, tmp_path):
    monkeypatch.setattr(driver, "SignifyClient", FakeClient)
    monkeypatch.setattr(driver.time, "sleep", lambda s: None)
    host = driver.Host("h", tmp_path, [])
    FakeClient.made, FakeClient.fails = 0, 3
    party = driver.Party(host, "p" * 21)
    assert (party.agent, party.controller, FakeClient.made) == ("agent", "ctrl", 4)
    FakeClient.made, FakeClient.fails = 0, driver.BOOT_ATTEMPTS
    with pytest.raises(requests.ConnectionError):
        driver.Party(host, "p" * 21)


def test_main_runs_the_plan_and_writes_the_export(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(entry.driver, "run", lambda plan, work: seen.append((plan, work)) or
                        {"ok": True})
    (tmp_path / "plan.json").write_text('{"seed": 1}')
    argv = [str(tmp_path / "plan.json"), str(tmp_path / "out.json"), str(tmp_path / "w")]
    assert entry.main(argv) == 0
    assert (tmp_path / "out.json").read_text() == '{"ok": true}'
    monkeypatch.setattr(entry.sys, "argv", ["kpa_keria_stack", *argv])
    assert entry.main() == 0
    assert seen[0] == ({"seed": 1}, tmp_path / "w") == seen[1]


def test_each_action_starts_in_a_wall_clock_second_of_its_own(monkeypatch):
    clock = iter([100.2, 100.7, 101.0, 105.5])
    slept = []
    monkeypatch.setattr(driver.time, "time", lambda: next(clock))
    monkeypatch.setattr(driver.time, "sleep", slept.append)
    world = driver.World.__new__(driver.World)
    world.timeline = []
    world._start("issue", 0)
    world._start("issue", 1)  # 100.7 shares second 100, so it waits for 101.0
    world._start("issue", 2)  # 105.5 is a new second already
    assert [t for _, _, t in world.timeline] == [100.2, 101.0, 105.5]
    assert slept == [pytest.approx(0.3)]


@pytest.mark.parametrize("readings", [(3600.5, 100.25), (101.99, 100.2), (101.7, 101.2)])
def test_a_clock_that_stepped_back_is_refused_not_waited_out(monkeypatch, readings):
    clock = iter(readings)
    monkeypatch.setattr(driver.time, "time", lambda: next(clock))
    world = driver.World.__new__(driver.World)
    world.timeline = []
    world._start("issue", 0)
    with pytest.raises(BakoboError) as exc:
        world._start("issue", 1)
    assert exc.value.code == "e.env.keria.clock-stepped.r"
