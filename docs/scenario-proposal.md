# The scored scenario set

Status: approved on 2026-10-28, before the scored runs. These claims and thresholds preceded their results. The reports state joins, bits, precision and completeness; none of them claims that anything is unlinkable.

## Baseline shared by the adapters

The executable scenarios are [`privacy-generator.toml`](../scenarios/privacy-generator.toml) and [`privacy-keria.toml`](../scenarios/privacy-keria.toml). They model 16 simulated citizens drawn from a 3.5 million-person population, four issuing homes, four fresh credential copies and four presentations per citizen. Two presentations are in the mandatory alcohol domain, at different verifiers; two are in the optional pharmacy domain. Presentation context is fixed at zero bits so the protocol increment is visible; this is an optimistic assumption for verifiers. The confidence cut is 1.0, so a completeness flag needs certain joins. All baseline compartments retain records indefinitely. A ten-year delayed disclosure exercises that retention.

Each real adapter uses only settings it can produce. KERIA issues into one issuer registry and presents the whole credential; its four verifiers therefore each receive all three modeled attributes. The generator baseline models a custodial issuer that keeps one registry per credential, allocates registries first in first out, issues a citizen's copies together and discloses selected fields. Comparisons must carry those disclosure and registry differences; equal scores are not expected. The same baseline was also run on a custodial-issuer stack whose adapter is not in this repository; those results are not published here.

| Party and variant | Obtains | Accepted terms | Predeclared claims |
|---|---|---|---|
| Two colluding verifiers; with and without terms | Public record and liquor-store plus pharmacy records | Both verifier compartments, or none | Re-identified citizens ≤ 0; with terms, re-identified on breach ≤ 0 |
| Four colluding verifiers; with and without terms | Public record and all four verifier records | All four verifier compartments, or none | Re-identified citizens ≤ 0; flagged domains ≤ 0; with terms, re-identified on breach ≤ 0 |
| Hacker, one home; all homes | Public record and home 0 with its operation rows, or homes 0–3 and the aggregate operation log | None | Citizens whose legal identity joins an issued identifier ≤ 0 |
| Hacker plus colluding verifiers | The same home data and all four verifier records | None | Re-identified citizens ≤ 0; for all homes, flagged domains ≤ 0 |
| Malicious revocation insider; with verifiers | Public record and revocation authority records, with or without all verifier records | None | With verifiers, re-identified citizens ≤ 0; alone, identity exposure ≤ 0 |
| Malicious Registrar or Observer log host insider; with verifiers | Public record and that host's access log, with or without all verifier records | None | With verifiers, re-identified citizens ≤ 0 |
| Malicious operations insider; with verifiers | Public record and aggregate durable operation log, with or without all verifier records | None | Alone, identity exposure ≤ 0; with verifiers, re-identified citizens ≤ 0 and flagged domains ≤ 0 |
| Another government office compelling disclosure, after ten years; with verifiers | Public record and home 0, with or without all verifier records | None; government compulsion overrides verifier terms | Alone, identity exposure ≤ 0; with verifiers, re-identified citizens ≤ 0 |
| Network observer at Registrar and Observer; with verifiers | Public record and both access logs, with or without all verifier records | None | With verifiers, re-identified citizens ≤ 0; flagged domains ≤ 0 |
| Network observer at hosted agent; with verifiers | Public record and hosted-agent access log, with or without all verifier records | None | With verifiers, re-identified citizens ≤ 0; flagged domains ≤ 0 |

The zero thresholds test strong claims. A failure is evidence to explain, not a reason to change the threshold after seeing a result. Every report also records join precision, identifying bits against log2(3.5 million) ≈ 21.74, protocol increment, and completeness. The mandatory alcohol domain is flagged when a citizen's two events are joined with certainty; optional pharmacy can be complete as a dataset but does not prove non-use.

The terms variants declare that each verifier has accepted chain-link confidentiality terms. The current adapters do not produce or verify a signed IPEX agreement for that term; these variants score the legal boundary as an explicit scenario premise, and report the technical joins again as a terms breach. They cannot establish that today's operators actually accepted enforceable terms.

The generator baseline includes a synthetic named credential record in each issuing home, to model a custodial home that retains clear copies of the credentials it issued. Sealing only the revocation map leaves those records present; an identity oracle removes them. This prevents the generator from assigning a privacy benefit to a map seal that does not erase the home's other identifying records (`this.i` 7wwc4pdd).

## Coverage limits to show in every report

KERIA has a hosted agent but no Observer or Registrar. A party holding a missing component must be reported as absent or not measured, never scored as protected. The generator's Observer, Registrar, and hosted-agent logs supply the positive controls for those attacks; [`privacy-generator-network.toml`](../scenarios/privacy-generator-network.toml) turns on hosted agents and holder status reads. Verifier bits are a lower bound wherever presented bytes are more precise than the declared attribute, such as a full birthDate behind an age band (tick 6hat).

## Generator sweeps, held to these settings before the baseline run

Each sweep changes one parameter from `privacy-generator.toml` and keeps the other parameters fixed. The same parties and claims apply. A sweep reports the full scores per value and plots bits and completeness; it does not silently pick a better threshold after seeing the curve.

| Variable | Values | Question |
|---|---|---|
| Issuing homes N | 1, 2, 4, 8, 16 | How much does the visible issuer AID partition citizens, and does random home assignment avoid attribute leakage? |
| Publication window in seconds | 0, 1, 60, 3600 | How much does batching Registrar publication obscure time joins? |
| TEL `dt` granularity in seconds | exact, 0.001, 1, 60, 3600 | How much time precision is enough to reconstruct a citizen's issuance session? |
| Retention in days, for home and access-log records | 0, 1, 365, infinity | Which joins remain available to a ten-year disclosure? |
| Registry allocation | FIFO, random | Does random allocation remove inception adjacency while leaving issuance adjacency? |
| Issuance order | per citizen, mixed | Does mixing break issuance adjacency? |
| Batch commitment | none; 4, 16, 64 with citizen-only, ordered, and mixed membership | Does a batch root link copies, and what anonymity set does a mixed batch leave? |
| Identity oracle, sealed revocation map, decoys | off/on; 0 or 16 decoys | Which State custody joins survive each proposed countermeasure? |

A 16-citizen run supports deterministic attack demonstrations, not a population prevalence estimate. Precision and recall must be read with their denominator.
