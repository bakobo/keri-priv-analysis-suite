"""`python -m kpa_keria_stack <plan.json> <export.json> <work dir>`: run a plan on KERIA and write
what every host stored. The adapter, in the suite's environment, runs this in this one."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import driver


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    plan, out, work = argv
    export = driver.run(json.loads(Path(plan).read_text()), Path(work))
    Path(out).write_text(json.dumps(export))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
