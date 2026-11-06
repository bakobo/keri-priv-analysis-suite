# Generator countermeasure sweeps

These are 35 scored variants of the approved
[`privacy-generator.toml`](../../scenarios/privacy-generator.toml). Each variant's scenario is in
[`scenarios/`](scenarios/), and [`manifest.json`](manifest.json) lists every value, scenario
digest and run directory. Each run's `results.json`, `report.md` and `report.json` are under
[`runs/`](runs/). The raw run directories (compartments, ground truth and attack joins) are kept
outside Git and hashed in the [raw-export manifest](../raw-exports.sha256); because the generator
is deterministic, `kpa run scenarios/<variant>.toml --out <dir>` reproduces any of them.
The three countermeasure "off" values refer to the separate
[baseline](../privacy-generator-baseline/report.md). The [comparison CSV](metrics.csv) and
[bits and completeness plot](bits-and-completeness.svg) are derived from the runs' `results.json`
and show three parties; every party's full scores are in each run's report.

One setting changes per variant. The home-count variants also make the "all homes"
parties obtain exactly the available homes, so their compartments remain valid.
Retention changes both issuing-home and access-log records. The population remains
3.5 million, with 16 simulated citizens, four copies and four presentations each,
and the approved zero thresholds remain fixed.

## What changed

| Setting | Measured effect |
|---|---|
| Homes, 1 to 16 | The many-verifier median rose from 4.00 to 7.99 identifying bits as the visible issuer partition got smaller. The all-homes hacker still exposed all 16 legal identities at every N. The one-home result changes with how many of this small sample land at home 0; it is not a prevalence estimate. |
| Publication window, 0 to 3600 seconds | No aggregate claim verdict or plotted metric changed. KEL first-seen times and issuance adjacency remained available. |
| TEL `dt`, exact to one hour | No aggregate claim verdict or plotted metric changed. Coarsening this timestamp alone left KEL first-seen times and issuance adjacency. |
| Home and access-log retention, 0 days to infinity | At 0 or 1 day, the 60-day all-homes hacker exposed 0 identities; at 365 days or infinity, it exposed all 16. At the ten-year compelled disclosure, 0, 1 and 365 days exposed 0 identities, while infinite retention exposed the one citizen at home 0. The many-verifier mandatory alcohol completeness remained 16/16. |
| FIFO versus random registry allocation | The registry-inception-adjacency attack alone fell from precision 1.0 and alcohol completeness 16/16 to precision 0.219 and completeness 2/16. Aggregate verdicts, median bits, and completeness did not change because other public timing and KEL joins, plus clear home records, remain. This is a generator counterfactual, not a result measured on a stack after a fix. |
| Per-citizen versus mixed issuance | The KEL-anchor-adjacency attack alone fell from precision 1.0 and alcohol completeness 16/16 to precision 0.240 and completeness 3/16. The many-verifier and ten-year compelled-home aggregate completeness fell from 16/16 to 3/16. The all-homes plus verifiers party still completed 16/16 through its home records. |
| Batch commitment, none or size 4, 16, 64 with citizen, ordered or mixed membership | Aggregate verdicts and plotted metrics did not change because other joins remained. The shared-batch-root attack alone flagged mandatory alcohol use for citizen-only batches at all three sizes and for ordered size 4; ordered or mixed membership at size 16 or 64 did not give that attack alone a complete citizen cluster. |
| Identity oracle off/on | All-homes identity exposure and re-identification fell from 16 to 0; many-verifier alcohol completeness stayed 16/16. The oracle variant removes the named home credential records as well as the direct map. |
| Sealed revocation map off/on | No aggregate improvement: the named credentials remain in each home and identify all 16 citizens. |
| Decoys, 0 or 16 | Many-verifier alcohol completeness fell from 16/16 to 8/16, but all-homes plus verifiers still reached 16/16 and re-identified all 16. |

These are deterministic examples under the generator's model. A flat aggregate curve
does not mean a setting had no effect on an individual attack. The full reports
record those attack scores and the causes and owners of each failed claim.
