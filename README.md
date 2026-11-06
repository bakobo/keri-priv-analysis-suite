# keri-priv-analysis-suite

[![CI](https://github.com/bakobo/keri-priv-analysis-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/bakobo/keri-priv-analysis-suite/actions/workflows/ci.yml)

Measures what a KERI/ACDC deployment lets each adversary join about a citizen, on any implementation. A deployment that issues bulk credential copies relies on mitigations such as one registry per credential and a fresh holder AID per copy to resist registry, timestamp, batch, AID and network-observation correlation. The suite tests those mitigations: for each party (colluding verifiers, a hacker or insider who obtains State data, a government office that compels disclosure, a network observer) it reports what that party can join, how many identifying bits the join yields per citizen, how certain it is and how complete. It never claims that something cannot be linked.

**Status: incubating.** The suite is developed at [Bakobo](https://bakobo.com) with the intention of contributing it to the KERI Foundation.

The intentions behind it are in [`this.i`](this.i), the approved test plan in [`docs/test-plan.md`](docs/test-plan.md), and the adapter interface in [`docs/adapters.md`](docs/adapters.md). The [scored findings](docs/privacy-findings.md) link to the generator and KERIA run evidence.

## Fresh clone to passing tests

You need [uv](https://docs.astral.sh/uv/) and the system libsodium (`sudo apt-get install libsodium23` on Debian and Ubuntu), which keripy loads.

```bash
uv sync
uv run pytest
```

The run fails below 100% branch coverage. It takes a few minutes, because the attack controls build real KELs and TELs with keripy.

## Running a scenario

A scenario file fixes everything a run depends on and refuses any parameter left unset. [`scenarios/smoke.toml`](scenarios/smoke.toml) is a few hundred citizens, two colluding verifiers and a hacker who obtains one issuing home, on the synthetic generator:

```bash
uv run kpa run scenarios/smoke.toml --out runs/smoke
```

To run a scenario on a real stack, run it from that adapter's project: `cd adapters/keria && uv run kpa run ../../scenarios/privacy-keria.toml --out <dir>`.

The run directory holds the scenario, the compartments every attack read, the ground truth kept apart from them, each party's joins and scores, `results.json`, and `report.md` and `report.json` generated from them. `kpa report <run-dir>` regenerates the report; `kpa check <scenario>` runs only the adapter contract suite. Git holds each scored run's reports and `results.json`, the sweep summaries and [`results/raw-exports.sha256`](results/raw-exports.sha256), which hashes the raw exports kept outside Git. A generator run is deterministic, so rerunning its scenario reproduces it.

## What is in it

- `src/keri_priv_analysis/`: the scenario loader, the population model, the compartment interface, the scorer, the attack catalogue (`attacks/`), the synthetic generator, the adapter contract suite, the runner and the report.
- `src/keri_priv_analysis/data/catalogue.toml`: which attacks answer each of the five correlation vectors, each predicted finding and each countermeasure, plus the non-claims and the gaps still open.
- `adapters/keria/`: KERIA agents driven by SignifyPy, its own uv project with its pins in `manifest.toml` and `uv.lock`. Its tests run the adapter contract suite against its stack live. See its README, and [`docs/adapters.md`](docs/adapters.md) to write another.
- `results/`: the scored generator and KERIA runs and the generator's countermeasure sweeps.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
