# Privacy analysis report

Scenario `abababababababababababababababababababababababababababababababab`, run on the generator adapter with suite 2026.10 and keripy 2.1.0.dev1 (commit unknown). The population has 20 rows (seed 1, sha256 `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd`).

## Measurement limits

- Verifier-side bits are a lower bound on what presentation bytes can reveal: the scorer counts declared attributes, while a selectively disclosed age-band presentation can carry a full birthDate (tick 6hat).

## Claims

| Party | Claim | Measured | Verdict |
|---|---|---|---|
| verifiers | reidentified <= 0 | 1 | fail |
| verifiers | max_bits <= 10 | 4.322 | pass |
| hacker | flagged_domains <= 0 | 1 | fail |
| hacker | precision >= 0.5 | not measured | not-measured |

## Failures

verifiers: reidentified <= 0 fails at 1.
- timestamp-clustering fails it alone. Cause: microsecond dt. Owner: the issuer.
- log-scan fails it alone. Cause: not stated by the adapter. Owner: everyone.

hacker: flagged_domains <= 0 fails at 1.
No single attack fails it; the attacks fail it only in combination.


## Parties

### verifiers (colluding-verifier)

Holds: public, verifier:v1, orchestrator (absent).
- orchestrator: Not built yet.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| timestamp-clustering | 3 | 0.667 | 1 | 1 |
| issuer-aid-bucket | 6 observations | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |

All attacks together make 3 joins, precision 0.667, recall 0.5. Citizens at or above the re-identification threshold of 4.322 bits: 1 of 3; median 2.5 bits, 90th percentile 4.322, maximum 4.322.
Sensitive attributes attached to re-identified citizens: veteran (1).
Citizens whose legal identity is joined to an identifier issued to them: 1.
Completeness in alcohol: median 0.5; citizens with every event in one cluster: 1. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 2; a breach of those terms would re-identify 3.
Bits the protocol adds over the party's own context: median 0.5, maximum 2.322.

### hacker (hacker)

Holds: issuing-home:0.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|

All attacks together make 3 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 4.322 bits: 1 of 0; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 1.
Joins its accepted terms forbid: 2; a breach of those terms would re-identify 3.
Bits the protocol adds over the party's own context: median 0, maximum 0.

## Attacks the catalogue does not yet make

Silence on these channels is not a result. Each is tracked in this repository's tick ledger.

- timestamps and nonces carried by the presentation protocol itself (tick 27nu)
- calibration of join confidence when citizens hold different numbers of copies (tick 2mcg)
- truncated, re-encoded and split identifiers in logs (tick 34kz)
- discovery material inside presentations, such as OOBI paths that name a citizen's agent (tick 3f3n)
- the sensitivity of bits to the population model's declared correlations (tick 3ikg)
- holder-side custodial stores: a mailbox's message store and a hosted agent's account database (tick 5aaa)
- timing joins between an asynchronous issuer's operation log and issuance anchors (tick 5im4)
- linkage across a credential's lifecycle: renewal, re-issuance, revocation cohorts and pool top-ups (tick 5sdj)
- recovering undisclosed low-entropy attributes from a compact block's SAID when the block carries no salt (tick 63ga)
- attribute values a presentation's bytes carry beyond what it declares disclosed (tick 6hat)
- active probing that needs a live stack, such as cache-warmth or response-timing oracles (tick 7pan)

## What this report does not claim

- a global passive network adversary
- transport-level fingerprints (TLS, connection reuse)
- re-identification from behavioural quasi-identifiers alone
- what a holder chooses to disclose, beyond counting its bits
- breach detection
