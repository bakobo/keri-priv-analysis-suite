# Scored privacy evidence

Status: scored. The [approved scenario set](scenario-proposal.md) fixes every claim threshold at zero, before any run. Each baseline has 16 simulated citizens, four credential copies per citizen, four presentations per citizen, four issuing homes and a 3.5 million-person population model. These deterministic examples show attack mechanisms, not how often a leak would occur in a real population.

## Results at a glance

| Adapter and run | Claims pass / fail / not measured | Two verifiers | Four verifiers | All homes plus verifiers |
|---|---:|---|---|---|
| [Generator baseline](../results/privacy-generator-baseline/report.md) | 12 / 9 / 2 | 16 certain joins, 0 re-identified | 96 certain joins, alcohol complete 16/16 | 16/16 legal identities exposed and re-identified |
| [Generator network positive control](../results/privacy-generator-network/report.md) | 13 / 10 / 0 | 16 certain joins, 0 re-identified | 96 certain joins, alcohol complete 16/16 | 16/16 legal identities exposed and re-identified |
| [KERIA with SignifyPy](../results/privacy-keria-baseline/report.md) | 14 / 3 / 6 | 82 certain joins at precision 0.8, 0 re-identified | 227 certain joins at precision 0.857, alcohol complete 16/16 | 0 legal identities exposed or re-identified in the measured home stores |

The four-verifier median is 5.993 identifying bits on the generator and 6.069 on KERIA. The simulated population's re-identification threshold is 21.739 bits. A zero in the re-identified column therefore does **not** mean there were no links: the certain joins and the complete mandatory-use domain are separate harms. The terms variants classify the same technical joins as forbidden by assumed accepted terms; the adapters do not prove that operators signed enforceable terms. KERIA presents the whole credential, while the generator baseline models selective disclosure, so their bits are not a controlled comparison of one credential format.

## What linked

- On the generator, which models a custodial issuer that allocates registries first in first out and issues a citizen's copies together, public KEL anchor order, registry inception order, exact TEL `dt` times and KEL first-seen times each complete the mandatory alcohol domain when four verifiers collude. Per-credential registries remove shared-registry equality, but these other joins remain. Each report names the cause and owner for each attack.
- A stolen issuing home that retains clear copies of the credentials it issued exposes each citizen assigned to it. Home 0 exposes the one simulated citizen assigned to it; all four homes expose all 16. With all verifier records, the all-homes hacker re-identifies all 16. A ten-year compelled disclosure of home 0 still exposes its one citizen under the predeclared infinite retention setting.
- KERIA's issuer-scoped registry, per-citizen anchor sequence, first-seen times and hosted-agent end roles produce certain cross-presentation joins and complete mandatory-use records. Its three failing zero-threshold claims are the four-verifier, all-homes-plus-verifiers and hosted-agent-plus-verifiers completeness claims. The KERIA adapter has no identity-proofing compartment; its zero legal-identity exposure under the measured home stores is scoped to that stack and those compartments.

## What did not link, and what was not measured

The two-verifier parties do not reach the population model's re-identification threshold in any baseline, despite their certain joins. The one-home hacker cannot identify citizens assigned to other homes. In KERIA, the measured home-only parties cannot attach a legal identity because that stack supplies no identity-proofing record. Those are scoped results; they do not certify a fleet that the adapters did not run.

The dedicated revocation-insider claims are not measured on KERIA because it has no separate revocation-authority access boundary: KERIA's issuer agent holds the credentials it would revoke. The one-home and all-homes parties, with and without verifier records, measure compromise of that actual store. The generator separately scores its modeled revocation-authority compartment. KERIA has no operation log, Registrar or Observer here, so the claims that require them are not measured. A not-measured claim is not a pass.

The catalogue still lacks a cross-compartment timing attack that uses an asynchronous issuer's operation milestone stamps against public issuance anchors (tick 5im4), and the generator does not yet model asynchronous operation rows (tick 5d76).

Verifier-side bits are a **lower bound** wherever the presented bytes are more precise than the declared attribute, such as a full birth date behind an age band (tick 6hat).

KERIA's timing joins depend on how fast the live run went: its credential and TEL `dt` values and KEL first-seen times are the stack's own wall-clock stamps (`adapters/keria/README.md`, "Determinism"). A rerun gives the same verdicts, bits and completeness, but timing attacks' join counts and precision can move: in this run the timestamp-clustering attack made some certain joins between different citizens whose copies were issued close together, which is why KERIA's verifier-party precision is below 1. Generator runs are deterministic.

Complete run directories, with scenarios, compartments, ground truth and attack joins, are kept outside Git and bound to these reports by the [SHA-256 manifest](../results/raw-exports.sha256). Git keeps each `results.json`, both rendered reports and the sweep summaries. Rerunning a generator scenario reproduces its run.

## Countermeasure sweep

The [35-variant generator sweep](../results/privacy-sweeps/README.md) includes its [scenarios](../results/privacy-sweeps/scenarios/), [manifest](../results/privacy-sweeps/manifest.json), [comparison CSV](../results/privacy-sweeps/metrics.csv) and [plot](../results/privacy-sweeps/bits-and-completeness.svg). Random registry allocation cut the registry-inception attack's precision from 1.0 to 0.219 and its alcohol completeness from 16/16 to 2/16, while other joins kept the aggregate four-verifier result complete. Mixed issuance cut the KEL-anchor attack's precision from 1.0 to 0.240 and its alcohol completeness from 16/16 to 3/16. These are generator counterfactuals, not results measured on a stack after a fix. Coarsening TEL time or widening the publication window alone left other exact timing and adjacency channels. One-year home retention removed the ten-year home disclosure join in the generator, but did not protect against a 60-day theft. Sealing the revocation map alone left named credential records in each home; an identity oracle removed them.

The full sweep reports distinguish each attack's change from an unchanged aggregate claim. A stack that implements random allocation, batch commitment or a mixing orchestrator needs a new scored run before any benefit is attributed to it.
