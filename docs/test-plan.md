# keri-priv-analysis-suite test plan

Status: approved on 2026-10-16, after its testability and maintainability reviews were dispositioned and applied. The intentions it rests on are in `this.i`.

The plan has two parts. Part A, the analysis plan, is what the suite measures and how. Part B covers how the suite's own code is tested, including how we know an attack that finds nothing has actually looked.

## Part A: the analysis plan

### Acceptance standard

The suite was built to test a deployment's privacy mitigations against five correlation vectors: shared registries, timestamps, batches, AIDs and network observation. It does not answer with a claim of unlinkability (`this.i` 8q5ylk4q). It answers with what each party can join, how many identifying bits that join yields per citizen, how certain it is, and how complete. Each of the five vectors maps to at least one attack in the catalogue below.

### Terms

These are used with exactly these meanings throughout the code and the reports.

| Term | Meaning |
|---|---|
| compartment | A body of stored data behind one access boundary, so that a single event exposes all of it together: one breach, one insider's credentials, one legal demand on its custodian. Two stores one administrator can read together are one compartment (`this.i` 9hztf0uy). |
| party | Someone who obtains one or more compartments. The kinds are a colluding verifier, a hacker, a malicious insider, a government party compelling disclosure, and a network observer (`this.i` 23c7h5vs, 5y304fhq). |
| presentation | One disclosure by one citizen to one verifier, at one time, of a stated set of attributes. |
| join | An attack's assertion that two presentations, or a presentation and a legal identity, belong to the same citizen, with a confidence in [0, 1]. A join with confidence 1 is certain. |
| cluster | A connected component of the graph whose edges are the joins an attack makes at or above a confidence cut. Joins compose: if A joins B and B joins C, the party holds A, B and C together. |
| bits | For a citizen, log2(P / m), where P is the size of the population the party searches and m is the number of people in it who match every attribute the party holds about that citizen's cluster. Every simulated citizen is a row of the population table, so m is at least 1 and bits never exceed log2(P). |
| completeness | For a citizen and an event domain, the share of that citizen's events in the domain that fall in one cluster. |
| bound join | A join the party has accepted terms forbidding (`this.i` 2leqqwzy). |
| positive control | A configuration built so that an attack's vector leaks. The attack must link it (`this.i` 97nt9ugu). |
| negative control | A configuration built so that an attack's vector does not leak. The attack must score at chance on it. |

### Scenarios

A scenario file fixes everything a run depends on, and a run refuses any parameter left unset. It holds:
- the population model: size P (3.5 million in the scored scenarios) and the joint distribution of attributes, given as a generated table of P rows from declared marginals and declared correlations, with its seed;
- the citizens simulated: how many, drawn as rows of the population table, which credentials each holds, and how many bulk copies of each;
- the presentations: per citizen, how many, to which verifiers, disclosing which attributes, in which event domain, and at what times;
- mandatory use: per event domain, whether a citizen in that domain must present a credential (`this.i` 4wrq8j56);
- the stack: which adapter, its settings, and which countermeasures are on (`this.i` 2gxskju4);
- the parties: per party, its kind, the compartments it obtains, the time it obtains them (retention is measured against that time, `this.i` 4ww9snv2), the terms it accepted, and the presentation context it has of its own (see below);
- the claims: each a party, a metric, and a threshold, all written before the run;
- the seed.

### Compartments the adapters expose

Each adapter returns every compartment the scenario names, as raw bytes and records, with ground truth held apart (`this.i` 364eng34). For a custodial issuer such as the one the scored scenarios model, the list is:
- the issuer's KEL, every TEL and the Registrar batches, as published (what the public and every verifier hold);
- each verifier's received presentations and its own logs;
- each issuing home's database (the pool table mapping registry to credential SAID to holder AID) and its application logs;
- the orchestrator store and an asynchronous issuer's operation log, where those exist;
- the revocation authority's records;
- the identity-proofing and IAR records;
- the access logs of witnesses, the Registrar, the Observer, watchers, holder-AID witnesses and mailboxes, and hosted agents.

A compartment that a stack does not have is reported as absent. A compartment that exists but that the adapter cannot export is reported as not measured, never as empty.

### The attack catalogue

Each attack reads compartment contents only and outputs joins. Every attack has a positive and a negative control, built by the synthetic generator.

The Origin column names where each attack came from. "The five vectors" means the vector list itself. The F codes are predictions made by reading a custodial issuer's source during the design review, before anything was run; the suite's first job is to confirm or refute each one:
- F1: the issuer reserves registries in FIFO order and issues all of one citizen's copies in a loop, so their issuance anchors, and their registries' inception seals, sit at nearby sequence numbers in the issuer's KEL.
- F2: every TEL event, blinded or not, carries a `dt` timestamp at microsecond precision, and one citizen's copies are issued milliseconds apart.
- F3: the issuing home keeps a durable map from registry to credential SAID to holder AID, which revocation needs.
- F4: whoever runs the Observer or Registrar sees which registry a verifier reads, when, and from where.
- F5: fresh holder AIDs per copy do not help if every copy's AID is served by the same witnesses, mailbox or OOBI host.
- F6: registries of one citizen whose sequence numbers advance together link by event count alone.
- F7: when batch commitment exists, a Merkle root shared by one citizen's copies links them, and a batch that mixes citizens makes its size the anonymity set.
- F8: with N issuing homes, which home signed splits holders into N buckets, about log2 N bits per presentation.
- F-J180: the issuer-AID bucket as first raised for homes sharded by region, date or agency.
- F-CVNP: a hosted citizen agent sits in the path of all of one citizen's traffic.

| Attack | Vector | Reads | Joins on | Positive control | Origin |
|---|---|---|---|---|---|
| shared registry | registry | presentations, TELs | two credentials in one registry | KERIA's ordinary usage: many credentials in one registry | the five vectors |
| KEL anchor adjacency | batch, AID | issuer KEL, presentations | issuance anchors at nearby sequence numbers | FIFO allocation, one citizen's copies issued in a loop | F1 |
| registry inception adjacency | registry | issuer KEL, TELs | `rip` seals at nearby sequence numbers | registries incepted in a loop and allocated in order | F1 |
| timestamp clustering | timestamp | TELs (including blinded `bup`), KEL | TEL event `dt` values close in time | microsecond `dt`, copies issued milliseconds apart | F2, public `upd` timing |
| event-count lock step | registry | TELs | registries whose sequence numbers advance together | one citizen's registries updated together | F6 |
| shared batch root | batch | membership proofs, anchors | two credentials under one Merkle root | batches holding one citizen's copies only | F7, generator only until a stack commits to batches |
| issuer-AID bucket | AID | presentations | which home signed; adds about log2 N bits rather than joining | homes sharded by region | F8, F-J180 |
| holder-AID infrastructure | AID, network | holder-AID witness, mailbox and OOBI logs | holder AIDs served by the same endpoints or contacted from one address | every copy's AID on one witness set and mailbox | F5 |
| registry-read logs | network | Observer and Registrar access logs | a verifier reading a registry, at a time, from an address | State-run Observer with full logs | F4 |
| hosted-agent logs | network | hosted-agent access logs | all of one citizen's traffic through one agent | one agent per citizen, full logs | F-CVNP |
| verifier probing | network | the verifier's own query timings | timing differences a verifier can induce | verifier queries before and after a known issuance | the design review |
| custodial join | all | issuing home database, orchestrator store, revocation records, identity proofing | the stored map from registry or SAID to holder AID to legal identity | the stored map, read directly | F3 |
| log scan | all | any log compartment | join material copied into a log (registry ids, SAIDs, holder AIDs next to each other or next to a legal identity) | logs with planted join material | `this.i` 4ww9snv2 |

Blinded `bup` is scored by running the shared-registry and timestamp attacks on a stack configured with it and without it.

### Metrics, per scenario and per party

- **Joins.** Precision and recall of the joins against ground truth, at each confidence cut, and the share of joins that are certain.
- **Bits.** For each simulated citizen, the bits the party accumulates: the attributes disclosed across that citizen's cluster, plus any legal-identity attributes a custodial join attaches, scored against the population table. Reported as a distribution, with the count of citizens at or above the re-identification threshold, log2(P) (about 22 bits for P = 3.5 million). Also reported: which sensitive attributes end up attached to a citizen above the threshold.
- **Completeness.** Per event domain, the distribution across citizens. A domain where completeness is 1 for any citizen whose joins are all certain is flagged, with whether mandatory use was on.
- **Bound joins.** Joins the party's accepted terms forbid are excluded from the harm totals and reported separately, as what a terms breach would expose. A government party compelling disclosure is never treated as bound.
- **Protocol increment.** Each verifier party declares, in the scenario, the bits its own presentation context gives it about each citizen (address, payment, cameras). The report gives the bits the protocol adds over that baseline. For a State compartment the baseline is zero (`this.i` 3tvy0xj4).

### Verdicts and the report

Each claim's verdict is pass or fail against its threshold, with the measurement beside it. For a failure, the report names the attack, the cause in the stack (file and line where the adapter can say), and an owner from a mapping file kept in this repo. The report is generated from the run's output directory only, never written by hand, and the word "unlinkable" does not appear in it. It ends with the non-claims:
- a global passive network adversary;
- transport-level fingerprints (TLS, connection reuse);
- re-identification from behavioural quasi-identifiers alone;
- what a holder chooses to disclose, beyond counting its bits;
- breach detection.

### Countermeasure sweeps

Each countermeasure in `this.i` 2gxskju4 is a scenario setting. A sweep runs the same scenario with the setting off and on, and for numeric settings (fleet size N, batch window, `dt` granularity, pool size, retention) across a grid, and plots bits and completeness against the setting. Countermeasures no stack implements are run on the synthetic generator only, and are labelled so.

### Topologies

- **KERIA with Signify,** driven through signifypy.
- **The synthetic generator,** which emits real KEL and TEL bytes with keripy from parameters, without witnesses (`this.i` 8zuzm3v3).

### Outputs

One complete directory per run is kept outside Git: the scenario file and its hash, provenance (component commits and versions, adapter versions, the population table's seed and hash), the compartment contents the attacks read, every attack's joins, the scores, and `report.md` and `report.json` derived from those. A disputed number can be recomputed from that directory, or by rerunning the scenario, which is deterministic on the generator. Git retains each run's `results.json` and rendered reports, sweep summaries, and a SHA-256 manifest of the omitted raw exports.

## Part B: tests of the suite itself

Development is strict TDD, with 100% branch coverage of new code, run by `uv run pytest`. Unit tests need no KERI stack.

1. **Controls.** For each attack, a test runs it on its positive control and requires precision 1.0 and recall at or above the recall the attack declares. A second test runs it on its negative control and requires precision indistinguishable from the base rate b, by a one-sided binomial test at α = 0.01 on a fixed seed. An attack without both tests fails the catalogue test (item 7).
   - For an attack that joins presentations to each other, b = Σ_c C(k_c, 2) / C(K, 2), where K is the number of presentations the attack considered and k_c the number of them belonging to citizen c. That is the precision of a guesser who joins pairs at random.
   - For an attack that joins presentations to legal identities, b = 1 / I, where I is the number of candidate identities in the compartments it read.
   - The negative control is generated large enough that the attack, if it joined at random, would make at least n joins, where n is the smallest sample giving the test power 0.95 to detect precision 2b. The test computes n from b and fails if the control is too small. An attack that makes no joins on its negative control passes, since its positive control shows it can find one.
   - The issuer-AID bucket attack adds bits rather than joins. Its negative control assigns holders to N homes uniformly at random, and the test requires the bits it reports to be within 0.05 of log2 N; its positive control shards homes by an attribute and requires the bits of that attribute on top.
2. **Isolation.** Attacks receive a compartment object that holds no ground truth. A test hands each attack a compartment set whose ground truth has been replaced with a permutation and requires identical joins.
3. **Scorer.** Hand-built join sets with known precision and recall, including joins that only compose through a third presentation. A hand-built population of twenty rows with known match counts checks the bits computation, including a citizen who crosses the threshold only after a second join. Completeness and its flag are checked on hand-built event domains with mandatory use on and off. Bound joins are checked to leave the harm totals and appear in the separate count. Expected values are derived inside each test file, never produced by the code under test.
4. **Population model.** A generated table matches its declared marginals and correlations within tolerance, and the same seed gives the same table, byte for byte.
5. **Adapter contract.** One contract suite, run against every adapter. Given a scenario, the adapter returns every compartment named, or marks it absent or not measured; the number of presentations exported equals the number the scenario specifies, per citizen and per verifier; every presentation in the ground truth maps to exactly one simulated citizen; every identifier in a compartment refers to an artifact the adapter issued; KEL and TEL bytes parse as CESR and verify with keripy. It runs against the generator on every change, and weekly in scheduled CI against each live adapter on its pinned stack versions. Each real adapter pins its stack in a committed manifest (each component's repository and commit SHA) and in the suite's `uv.lock`. The scheduled job installs exactly those, refuses a stale lockfile (`uv sync --locked`), and records the manifest's hash in provenance. Changing a pin is a commit.
6. **Generator fidelity.** For one shared set of parameters, every attack's verdict on the generator's output equals its verdict on the live custodial-issuer adapter's output, except any exact, asserted difference from evidence the generator does not model, such as an asynchronous issuer's durable operation records (`this.i` 8ps45j4u). The bits distributions agree within a stated tolerance. This runs with the live adapter, since it needs the stack; the custodial-issuer adapter it was first run against is not in this repository.
7. **Catalogue coverage.** A mapping file lists the five vectors, findings F1–F8, F-J180 and F-CVNP, and the countermeasures in `this.i` 2gxskju4. A test requires each vector and finding to map to at least one attack or to a named non-claim, each countermeasure to map to a scenario setting, and each attack to have both controls.
8. **Scenario.** An unset parameter, an unknown compartment name, a party kind outside the five, and terms on a compelling government party are each refused with a coded error. The same scenario and seed produce a byte-identical report.
9. **Report.** Golden tests on small hand-built runs. A test fails if the rendered report contains "unlinkab" in any form, omits the non-claims, or omits the verifier-bits lower-bound limit from either rendered format.
10. **Log scan.** Logs with join material planted in known places, in known formats, are scanned and every plant is found; logs without plants produce no joins.
11. **CI.** From the first code commit, CI runs `uv run pytest` with branch coverage and fails below 100%, on every push and pull request. The scheduled job (items 5 and 6) runs weekly.

## Depends on

- An asynchronous issuer's operation log and a fleet orchestrator are compartments the suite reads where a stack has them, and reports absent where it does not.
- Batch commitment. Until a stack commits to batches, the shared-batch-root attack runs on the generator only.
- Random registry allocation and mixed issuance order are generator counterfactuals until a stack implements them; later runs show what a landed fix buys.

## Left to later work

- Fixes for whatever the report finds, owned by the components the report names.
- Breach detection by canaries.
