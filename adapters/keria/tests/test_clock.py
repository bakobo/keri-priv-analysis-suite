from datetime import UTC, datetime

from kpa_adapter_keria.clock import PROVISIONING, Clock
from kpa_adapter_keria.plan import Issuance, Plan, Showing


def plan():
    return Plan(rows=[], homes=[], attributes=[],
                issuance=[Issuance(0, 0, 100.0), Issuance(0, 1, 100.004)],
                showings=[Showing("h", 0, 0, "v", "d", 9000.0, ("a",))], driver={})


TIMELINE = [["provision", -1, 1000.2], ["issue", 0, 1010.5], ["issue", 1, 1012.9],
            ["present", 0, 1020.1]]


def test_precise_times_take_the_latest_action_started():
    clock = Clock(TIMELINE, plan())
    assert clock.at(999.0) == PROVISIONING  # before anything: provisioning
    assert clock.at(1010.4) == PROVISIONING
    assert clock.at(1010.5) == 100.0
    assert clock.at(1013.0) == 100.004
    assert clock.at(5000.0) == 9000.0


def test_log_lines_compare_by_the_second():
    clock = Clock(TIMELINE, plan())
    assert clock.at_second(1010.0) == 100.0  # the issuance started during that second
    assert clock.at_second(1009.0) == PROVISIONING
    assert clock.at_second(1012.0) == 100.004


def test_stamps_are_read_as_rfc3339():
    clock = Clock(TIMELINE, plan())
    stamp = datetime.fromtimestamp(1020.5, tz=UTC).isoformat()
    assert clock.at_stamp(stamp) == 9000.0
