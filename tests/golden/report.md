# Privacy analysis: generator adapter

This report says what each adversary in one scenario could learn about simulated citizens by correlating the data it holds, and whether each claim written before the run held. [How to read it](https://bakobo.github.io/keri-priv-analysis-suite/reading-a-report/), and the [glossary](https://bakobo.github.io/keri-priv-analysis-suite/glossary/) for any term.

Scenario `abababababababababababababababababababababababababababababababab`, run on the generator adapter with suite 2026.10 and keripy 2.1.0.dev1 (commit unknown). The population has 20 rows (seed 1, sha256 `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd`).

## What each adversary learns

- [verifiers](#verifiers): 3 correlations, precision 0.667, of which its accepted terms forbid 2 and so are not counted as harm (a breach would re-identify 3); re-identifies 1 of 3 citizens; attaches a legal identity to 1; ties all of some citizens' uses of a kind together: 1 of 3 in alcohol, proven. This stack does not have the orchestrator's store, so the party was measured on the rest of what it would hold. Claims: 1 fails, 1 holds.
- [hacker](#hacker): 3 correlations, precision not measured, of which its accepted terms forbid 2 and so are not counted as harm (a breach would re-identify 3); re-identifies 1 of 0 citizens; attaches a legal identity to 1; ties no citizen's uses of any kind all together. Claims: 1 fails, 1 not measured.

## Claims

Each claim was written into the scenario before the run.

| Party | Claim | Measured | [Verdict](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#claim-and-verdict "Whether the claim, written before the run, held: holds, fails, or not measured when the party lacked what the claim needs.") |
|---|---|---|---|
| [verifiers](#verifiers) | The party re-identifies no simulated citizen, singling none out from the population. | 1 | fails |
| [verifiers](#verifiers) | For the party, the most identifying bits it gathers about any one simulated citizen is at most 10. | 4.322 | holds |
| [hacker](#hacker) | The party cannot prove, for any citizen, that it holds every one of that citizen's credential uses of some kind (every alcohol purchase, say). | 1 | fails |
| [hacker](#hacker) | For the party, the share of its correlations that are correct is at least 0.5. | not measured | not measured |

## Why claims fail

[verifiers](#verifiers). Claim: the party re-identifies no simulated citizen, singling none out from the population. It fails: measured 1.

- [Timestamp clustering](https://bakobo.github.io/keri-priv-analysis-suite/attacks/#timestamp-clustering-timestamp-clustering "Every credential's registry entry carries the time it was issued, to the microsecond. One citizen's copies are issued milliseconds apart, so their times stand out as a cluster.") is enough on its own. Cause: microsecond dt. Owner: the issuer.
- [Correlations copied into logs](https://bakobo.github.io/keri-priv-analysis-suite/attacks/#correlations-copied-into-logs-log-scan "Logs that write two identifiers on one line, or tag related lines with one request or session id, tie together whatever they name. This attack searches every log a party holds.") is enough on its own. Cause: not stated by the adapter. Owner: everyone.

[hacker](#hacker). Claim: the party cannot prove, for any citizen, that it holds every one of that citizen's credential uses of some kind (every alcohol purchase, say). It fails: measured 1.

No single attack fails it; the attacks fail it only in combination.


## Measurement limits

- Verifier-side bits are a lower bound on what presentation bytes can reveal: the scorer counts declared attributes, while a selectively disclosed age-band presentation can carry a full birthDate (tick 6hat).

## Parties

### verifiers

Businesses that check citizens' credentials, such as a liquor store or a pharmacy, and pool the records they kept of each presentation. This party holds [the public record](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#compartment "Issuers' key event logs, credential registries' logs and published batches, which anyone can read."), [the v1's records](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#compartment "The records a verifier kept of the presentations it received."), [the orchestrator's store](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#compartment "The store of the service that coordinates issuance across the issuing homes.") (absent).

What the adapter put in each:

- the orchestrator's store: Not built yet.

| [Attack](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#attack "One way of correlating. Each reads only what a party holds, and proves on a test setup that it can find a link before its silence counts.") | [Correlations](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#correlation "A link an attack makes between two things it holds, such as two presentations, saying they belong to the same citizen.") | [Precision](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#precision "Of the correlations an attack made, the share that are correct. 1 means none is wrong.") | [Certain](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#certain "The share of an attack's correlations that rest on proof, such as a shared identifier, rather than on likelihood.") | [Re-identified alone](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#re-identified "A simulated citizen about whom the party gathers enough identifying bits to single them out of the whole population.") |
|---|---|---|---|---|
| [Timestamp clustering](https://bakobo.github.io/keri-priv-analysis-suite/attacks/#timestamp-clustering-timestamp-clustering "Every credential's registry entry carries the time it was issued, to the microsecond. One citizen's copies are issued milliseconds apart, so their times stand out as a cluster.") | 3 | 0.667 | 1 | 1 |
| [Which issuing home signed](https://bakobo.github.io/keri-priv-analysis-suite/attacks/#which-issuing-home-signed-issuer-aid-bucket "A presentation shows which of the State's issuing homes signed it. That does not tie presentations together, but it narrows down who the citizen is by about log2 N bits for N homes, more if homes serve particular regions.") | 6 observations | not measured | not measured | 0 |
| [One hosted agent per citizen](https://bakobo.github.io/keri-priv-analysis-suite/attacks/#one-hosted-agent-per-citizen-hosted-agent "A cloud agent that runs a citizen's wallet sees all of that citizen's traffic, so its host's logs tie together every identifier it serves.") | not measured: needs the hosted-agent service's access log | | | |

All attacks together make 3 [correlations](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#correlation "A link an attack makes between two things it holds, such as two presentations, saying they belong to the same citizen."), [precision](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#precision "Of the correlations an attack made, the share that are correct. 1 means none is wrong.") 0.667, [recall](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#recall "Of the correlations that could have been made, the share the attacks made.") 0.5. [Re-identified](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#re-identified "A simulated citizen about whom the party gathers enough identifying bits to single them out of the whole population.") citizens, those at or above 4.322 [identifying bits](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#identifying-bits "How much a party's correlated data narrows down who a citizen is. Each bit halves the number of people who fit."): 1 of 3; median 2.5 bits, 90th percentile 4.322, maximum 4.322.
Sensitive attributes attached to re-identified citizens: veteran (1).
Citizens whose legal identity it attaches to an identifier issued to them: 1.
[Completeness](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#completeness "The share of a citizen's uses of one kind (alcohol purchases, say) that the party has tied together.") in alcohol: median 0.5; citizens with every use tied together: 1. Flagged: the party can prove it holds every one of some citizen's uses of this kind, and use is mandatory.
[Completeness](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#completeness "The share of a citizen's uses of one kind (alcohol purchases, say) that the party has tied together.") in pharmacy: median 0; citizens with every use tied together: 0.
Correlations its accepted terms forbid: 2; a breach of those terms would re-identify 3.
Bits the protocol adds over the party's own context: median 0.5, maximum 2.322.

### hacker

Someone who breaks into State systems and takes everything those systems hold. This party holds [issuing home 0](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#compartment "One of the State's servers that issue credentials: its database and its logs.").

| [Attack](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#attack "One way of correlating. Each reads only what a party holds, and proves on a test setup that it can find a link before its silence counts.") | [Correlations](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#correlation "A link an attack makes between two things it holds, such as two presentations, saying they belong to the same citizen.") | [Precision](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#precision "Of the correlations an attack made, the share that are correct. 1 means none is wrong.") | [Certain](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#certain "The share of an attack's correlations that rest on proof, such as a shared identifier, rather than on likelihood.") | [Re-identified alone](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#re-identified "A simulated citizen about whom the party gathers enough identifying bits to single them out of the whole population.") |
|---|---|---|---|---|

All attacks together make 3 [correlations](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#correlation "A link an attack makes between two things it holds, such as two presentations, saying they belong to the same citizen."), [precision](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#precision "Of the correlations an attack made, the share that are correct. 1 means none is wrong.") not measured, [recall](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#recall "Of the correlations that could have been made, the share the attacks made.") not measured. [Re-identified](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#re-identified "A simulated citizen about whom the party gathers enough identifying bits to single them out of the whole population.") citizens, those at or above 4.322 [identifying bits](https://bakobo.github.io/keri-priv-analysis-suite/glossary/#identifying-bits "How much a party's correlated data narrows down who a citizen is. Each bit halves the number of people who fit."): 1 of 0; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity it attaches to an identifier issued to them: 1.
Correlations its accepted terms forbid: 2; a breach of those terms would re-identify 3.
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
