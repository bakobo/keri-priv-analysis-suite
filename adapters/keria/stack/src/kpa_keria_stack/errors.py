"""Every error the KERIA stack driver raises, declared once at module scope
(dev/standards/error-codes.md)."""

from bakobo.errors import ErrorCode

HOST_EXITED = ErrorCode(
    "e.env.keria.exited.r",
    "A KERIA agency exited before it was ready.",
    detail="The KERIA agency for {host} exited with code {code} before it was ready to serve. "
    "Its log is {log}.",
    args=("host", "code", "log"),
    hint="Read the log's last lines; a port another process took is the usual cause.",
)
HOST_TIMEOUT = ErrorCode(
    "e.env.keria.timeout.r",
    "A KERIA agency did not become ready in time.",
    detail="The KERIA agency for {host} was not ready after {seconds} seconds. Its log is {log}.",
    args=("host", "seconds", "log"),
    hint="A heavily loaded machine starts KERIA slowly; try again when it is quieter.",
)
WAIT_TIMEOUT = ErrorCode(
    "e.env.keria.wait.r",
    "KERIA did not finish a step in time.",
    detail="Waiting for {what} gave up after {seconds} seconds.",
    args=("what", "seconds"),
    hint="The hosts' logs in the work directory say what each agency was doing.",
)
CLOCK_STEPPED = ErrorCode(
    "e.env.keria.clock-stepped.r",
    "The wall clock stepped back while the KERIA driver ran.",
    detail="The wall clock read {now} after an action started at {last}.",
    args=("now", "last"),
    hint="KERIA's logs are stamped by the wall clock, so a run across a large clock step cannot "
    "place them; run again once the clock is steady.",
)
PLAN_FORMAT = ErrorCode(
    "e.input.format.keria-plan.f",
    "The plan the adapter handed the KERIA driver is malformed.",
    detail="The plan is missing {key!r} or holds it in the wrong form.",
    args=("key",),
    hint="The adapter writes the plan; a mismatch means the two projects are out of step.",
)
