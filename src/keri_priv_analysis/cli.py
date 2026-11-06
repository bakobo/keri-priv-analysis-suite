"""kpa: run a scenario, regenerate a report, or check an adapter against the contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from bakobo.errors import BakoboError

from . import contract, report, runner
from .population import generate
from .scenario import load


def _run(args) -> int:
    out = runner.run(Path(args.scenario).read_text(), Path(args.out))
    print(f"wrote {out / 'report.md'}")
    return 0


def _report(args) -> int:
    report.write(Path(args.run))
    print(f"wrote {Path(args.run) / 'report.md'}")
    return 0


def _check(args) -> int:
    scenario = load(Path(args.scenario))
    adapter = runner.adapter_for(scenario.run.adapter)
    population = generate(scenario.population)
    problems = contract.check(scenario, *adapter.run(scenario, population), population)
    for problem in problems:
        print(problem)
    print(f"{adapter.name}: {len(problems)} contract problems")
    return 1 if problems else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="kpa", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run", help="run a scenario into a new run directory")
    p.add_argument("scenario")
    p.add_argument("--out", required=True)
    p.set_defaults(func=_run)
    p = sub.add_parser("report", help="regenerate report.md and report.json from a run directory")
    p.add_argument("run")
    p.set_defaults(func=_report)
    p = sub.add_parser("check", help="run the adapter contract suite on a scenario's adapter")
    p.add_argument("scenario")
    p.set_defaults(func=_check)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BakoboError as exc:
        print(f"kpa: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
