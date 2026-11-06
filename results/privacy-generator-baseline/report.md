# Privacy analysis report

Scenario `252f9a91ae0a5301e633a97aa362a8ce1ffc2d029643e0954fe2a596ba559b9f`, run on the generator adapter with suite 2026.10 and keripy 2.1.0.dev1 (910dcb350e63d3129c91345429c1fa10f2dae5e5). The population has 3500000 rows (seed 1, sha256 `a143ac0841eb99e8313f7908e7e5b97f976647025adbcd96cc1d4f4cc1cf9a3d`).

## Measurement limits

- Verifier-side bits are a lower bound on what presentation bytes can reveal: the scorer counts declared attributes, while a selectively disclosed age-band presentation can carry a full birthDate (tick 6hat).

## Claims

| Party | Claim | Measured | Verdict |
|---|---|---|---|
| two-verifiers | reidentified <= 0 | 0 | pass |
| two-verifiers-terms | reidentified <= 0 | 0 | pass |
| two-verifiers-terms | breach_reidentified <= 0 | 0 | pass |
| many-verifiers | reidentified <= 0 | 0 | pass |
| many-verifiers | flagged_domains <= 0 | 2 | fail |
| many-verifiers-terms | reidentified <= 0 | 0 | pass |
| many-verifiers-terms | flagged_domains <= 0 | 0 | pass |
| many-verifiers-terms | breach_reidentified <= 0 | 0 | pass |
| one-home-hacker | identity_exposed <= 0 | 1 | fail |
| all-homes-hacker | identity_exposed <= 0 | 16 | fail |
| one-home-with-verifiers | reidentified <= 0 | 1 | fail |
| all-homes-with-verifiers | reidentified <= 0 | 16 | fail |
| all-homes-with-verifiers | flagged_domains <= 0 | 2 | fail |
| revocation-insider | identity_exposed <= 0 | 0 | pass |
| revocation-insider-with-verifiers | reidentified <= 0 | 0 | pass |
| registrar-insider-with-verifiers | reidentified <= 0 | 0 | pass |
| observer-insider-with-verifiers | reidentified <= 0 | 0 | pass |
| compelled-home | identity_exposed <= 0 | 1 | fail |
| compelled-home-with-verifiers | reidentified <= 0 | 1 | fail |
| registrar-observer-with-verifiers | reidentified <= 0 | 0 | pass |
| registrar-observer-with-verifiers | flagged_domains <= 0 | 2 | fail |
| hosted-agent-with-verifiers | reidentified <= 0 | 0 | not-measured |
| hosted-agent-with-verifiers | flagged_domains <= 0 | 2 | not-measured |

## Failures

many-verifiers: flagged_domains <= 0 fails at 2.
- kel-anchor-adjacency fails it alone. Cause: the generator's stack settings issuance_order = 'per-citizen', decoys = 0. Owner: the issuer and any orchestrator: mix issuance order across citizens.
- kel-first-seen fails it alone. Cause: the generator's stack settings first_seen = 'exact', issuance_order = 'per-citizen'. Owner: the issuer and the holder's wallet: the first-seen times a published KEL replay carries.
- registry-inception-adjacency fails it alone. Cause: the generator's stack settings registry_allocation = 'fifo', issuance_order = 'per-citizen'. Owner: the issuer: random registry allocation.
- timestamp-clustering fails it alone. Cause: the generator's stack settings dt_granularity = 0.0, issuance_order = 'per-citizen'. Owner: the issuer, any orchestrator and batch commitment: coarse dt.

one-home-hacker: identity_exposed <= 0 fails at 1.
- custodial-join fails it alone. Cause: the generator's stack settings sealed_revocation_map = False, identity_oracle = False. Owner: the issuing home: the pool table and the revocation map.

all-homes-hacker: identity_exposed <= 0 fails at 16.
- custodial-join fails it alone. Cause: the generator's stack settings sealed_revocation_map = False, identity_oracle = False. Owner: the issuing home: the pool table and the revocation map.

one-home-with-verifiers: reidentified <= 0 fails at 1.
- custodial-join fails it alone. Cause: the generator's stack settings sealed_revocation_map = False, identity_oracle = False. Owner: the issuing home: the pool table and the revocation map.

all-homes-with-verifiers: reidentified <= 0 fails at 16.
- custodial-join fails it alone. Cause: the generator's stack settings sealed_revocation_map = False, identity_oracle = False. Owner: the issuing home: the pool table and the revocation map.

all-homes-with-verifiers: flagged_domains <= 0 fails at 2.
- custodial-join fails it alone. Cause: the generator's stack settings sealed_revocation_map = False, identity_oracle = False. Owner: the issuing home: the pool table and the revocation map.
- kel-anchor-adjacency fails it alone. Cause: the generator's stack settings issuance_order = 'per-citizen', decoys = 0. Owner: the issuer and any orchestrator: mix issuance order across citizens.
- kel-first-seen fails it alone. Cause: the generator's stack settings first_seen = 'exact', issuance_order = 'per-citizen'. Owner: the issuer and the holder's wallet: the first-seen times a published KEL replay carries.
- registry-inception-adjacency fails it alone. Cause: the generator's stack settings registry_allocation = 'fifo', issuance_order = 'per-citizen'. Owner: the issuer: random registry allocation.
- timestamp-clustering fails it alone. Cause: the generator's stack settings dt_granularity = 0.0, issuance_order = 'per-citizen'. Owner: the issuer, any orchestrator and batch commitment: coarse dt.

compelled-home: identity_exposed <= 0 fails at 1.
- custodial-join fails it alone. Cause: the generator's stack settings sealed_revocation_map = False, identity_oracle = False. Owner: the issuing home: the pool table and the revocation map.

compelled-home-with-verifiers: reidentified <= 0 fails at 1.
- custodial-join fails it alone. Cause: the generator's stack settings sealed_revocation_map = False, identity_oracle = False. Owner: the issuing home: the pool table and the revocation map.

registrar-observer-with-verifiers: flagged_domains <= 0 fails at 2.
- kel-anchor-adjacency fails it alone. Cause: the generator's stack settings issuance_order = 'per-citizen', decoys = 0. Owner: the issuer and any orchestrator: mix issuance order across citizens.
- kel-first-seen fails it alone. Cause: the generator's stack settings first_seen = 'exact', issuance_order = 'per-citizen'. Owner: the issuer and the holder's wallet: the first-seen times a published KEL replay carries.
- registry-inception-adjacency fails it alone. Cause: the generator's stack settings registry_allocation = 'fifo', issuance_order = 'per-citizen'. Owner: the issuer: random registry allocation.
- timestamp-clustering fails it alone. Cause: the generator's stack settings dt_granularity = 0.0, issuance_order = 'per-citizen'. Owner: the issuer, any orchestrator and batch commitment: coarse dt.


## Parties

### all-homes-hacker (hacker)

Holds: issuing-home:0, issuing-home:1, issuing-home:2, issuing-home:3, public.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | 768 | not measured | 1 | 0 |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs access-log:hosted-agent; verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | not measured: needs verifier | | | |
| registry-inception-adjacency | not measured: needs verifier | | | |
| registry-reads | not measured: needs access-log:observer or access-log:registrar; verifier | | | |
| shared-anchor | not measured: needs verifier | | | |
| shared-batch-root | not measured: needs verifier | | | |
| shared-holder | not measured: needs verifier | | | |
| shared-registry | not measured: needs verifier | | | |
| timestamp-clustering | not measured: needs verifier | | | |
| verifier-probing | not measured: needs verifier | | | |
| witness-arrival | not measured: needs access-log:witness; verifier | | | |

All attacks together make 768 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 16.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### all-homes-with-verifiers (hacker)

Holds: issuing-home:0, issuing-home:1, issuing-home:2, issuing-home:3, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | 1120 | 1 | 1 | 16 |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 1120 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 16 of 16; median 21.739 bits, 90th percentile 21.739, maximum 21.739.
Citizens whose legal identity is joined to an identifier issued to them: 16.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 16.
Bits the protocol adds over the party's own context: median 21.739, maximum 21.739.

### compelled-home (government)

Holds: issuing-home:0, public.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | 48 | not measured | 1 | 0 |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs access-log:hosted-agent; verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | not measured: needs verifier | | | |
| registry-inception-adjacency | not measured: needs verifier | | | |
| registry-reads | not measured: needs access-log:observer or access-log:registrar; verifier | | | |
| shared-anchor | not measured: needs verifier | | | |
| shared-batch-root | not measured: needs verifier | | | |
| shared-holder | not measured: needs verifier | | | |
| shared-registry | not measured: needs verifier | | | |
| timestamp-clustering | not measured: needs verifier | | | |
| verifier-probing | not measured: needs verifier | | | |
| witness-arrival | not measured: needs access-log:witness; verifier | | | |

All attacks together make 48 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 1.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### compelled-home-with-verifiers (government)

Holds: issuing-home:0, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | 70 | 1 | 1 | 1 |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 160 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 1 of 16; median 6.313 bits, 90th percentile 8.397, maximum 21.739.
Citizens whose legal identity is joined to an identifier issued to them: 1.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 1.
Bits the protocol adds over the party's own context: median 6.313, maximum 21.739.

### hosted-agent-network (network-observer)

Holds: access-log:hosted-agent (absent), public.
- access-log:hosted-agent: No hosted agents in this configuration.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs access-log:hosted-agent; verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | not measured: needs verifier | | | |
| registry-inception-adjacency | not measured: needs verifier | | | |
| registry-reads | not measured: needs access-log:observer or access-log:registrar; verifier | | | |
| shared-anchor | not measured: needs verifier | | | |
| shared-batch-root | not measured: needs verifier | | | |
| shared-holder | not measured: needs verifier | | | |
| shared-registry | not measured: needs verifier | | | |
| timestamp-clustering | not measured: needs verifier | | | |
| verifier-probing | not measured: needs verifier | | | |
| witness-arrival | not measured: needs access-log:witness; verifier | | | |

All attacks together make 0 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### hosted-agent-with-verifiers (network-observer)

Holds: access-log:hosted-agent (absent), public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- access-log:hosted-agent: No hosted agents in this configuration.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 96 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 5.993 bits, 90th percentile 7.725, maximum 8.397.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 5.993, maximum 8.397.

### many-verifiers (colluding-verifier)

Holds: public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 96 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 5.993 bits, 90th percentile 7.725, maximum 8.397.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 5.993, maximum 8.397.

### many-verifiers-terms (colluding-verifier)

Holds: public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | not measured | 1 | 0 |
| kel-first-seen | 96 | not measured | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | not measured | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | not measured | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 96 joins, precision not measured, recall 0. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 4.162 bits, 90th percentile 5.182, maximum 6.065.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0.5; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0.5; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 96; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 4.162, maximum 6.065.

### observer-insider (insider)

Holds: access-log:observer, public.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs access-log:hosted-agent; verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | not measured: needs verifier | | | |
| registry-inception-adjacency | not measured: needs verifier | | | |
| registry-reads | not measured: needs verifier | | | |
| shared-anchor | not measured: needs verifier | | | |
| shared-batch-root | not measured: needs verifier | | | |
| shared-holder | not measured: needs verifier | | | |
| shared-registry | not measured: needs verifier | | | |
| timestamp-clustering | not measured: needs verifier | | | |
| verifier-probing | not measured: needs verifier | | | |
| witness-arrival | not measured: needs access-log:witness; verifier | | | |

All attacks together make 0 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### observer-insider-with-verifiers (insider)

Holds: access-log:observer, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | 0 | not measured | not measured | 0 |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 96 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 5.993 bits, 90th percentile 7.725, maximum 8.397.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 5.993, maximum 8.397.

### one-home-hacker (hacker)

Holds: issuing-home:0, public.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | 48 | not measured | 1 | 0 |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs access-log:hosted-agent; verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | not measured: needs verifier | | | |
| registry-inception-adjacency | not measured: needs verifier | | | |
| registry-reads | not measured: needs access-log:observer or access-log:registrar; verifier | | | |
| shared-anchor | not measured: needs verifier | | | |
| shared-batch-root | not measured: needs verifier | | | |
| shared-holder | not measured: needs verifier | | | |
| shared-registry | not measured: needs verifier | | | |
| timestamp-clustering | not measured: needs verifier | | | |
| verifier-probing | not measured: needs verifier | | | |
| witness-arrival | not measured: needs access-log:witness; verifier | | | |

All attacks together make 48 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 1.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### one-home-with-verifiers (hacker)

Holds: issuing-home:0, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | 70 | 1 | 1 | 1 |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 160 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 1 of 16; median 6.313 bits, 90th percentile 8.397, maximum 21.739.
Citizens whose legal identity is joined to an identifier issued to them: 1.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 1.
Bits the protocol adds over the party's own context: median 6.313, maximum 21.739.

### registrar-insider (insider)

Holds: access-log:registrar, public.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs access-log:hosted-agent; verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | not measured: needs verifier | | | |
| registry-inception-adjacency | not measured: needs verifier | | | |
| registry-reads | not measured: needs verifier | | | |
| shared-anchor | not measured: needs verifier | | | |
| shared-batch-root | not measured: needs verifier | | | |
| shared-holder | not measured: needs verifier | | | |
| shared-registry | not measured: needs verifier | | | |
| timestamp-clustering | not measured: needs verifier | | | |
| verifier-probing | not measured: needs verifier | | | |
| witness-arrival | not measured: needs access-log:witness; verifier | | | |

All attacks together make 0 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### registrar-insider-with-verifiers (insider)

Holds: access-log:registrar, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | 0 | not measured | not measured | 0 |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 96 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 5.993 bits, 90th percentile 7.725, maximum 8.397.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 5.993, maximum 8.397.

### registrar-observer-network (network-observer)

Holds: access-log:observer, access-log:registrar, public.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs access-log:hosted-agent; verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | not measured: needs verifier | | | |
| registry-inception-adjacency | not measured: needs verifier | | | |
| registry-reads | not measured: needs verifier | | | |
| shared-anchor | not measured: needs verifier | | | |
| shared-batch-root | not measured: needs verifier | | | |
| shared-holder | not measured: needs verifier | | | |
| shared-registry | not measured: needs verifier | | | |
| timestamp-clustering | not measured: needs verifier | | | |
| verifier-probing | not measured: needs verifier | | | |
| witness-arrival | not measured: needs access-log:witness; verifier | | | |

All attacks together make 0 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### registrar-observer-with-verifiers (network-observer)

Holds: access-log:observer, access-log:registrar, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | 0 | not measured | not measured | 0 |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 96 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 5.993 bits, 90th percentile 7.725, maximum 8.397.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 5.993, maximum 8.397.

### revocation-insider (insider)

Holds: public, revocation-authority.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | 0 | not measured | not measured | 0 |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs access-log:hosted-agent; verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | not measured: needs verifier | | | |
| registry-inception-adjacency | not measured: needs verifier | | | |
| registry-reads | not measured: needs access-log:observer or access-log:registrar; verifier | | | |
| shared-anchor | not measured: needs verifier | | | |
| shared-batch-root | not measured: needs verifier | | | |
| shared-holder | not measured: needs verifier | | | |
| shared-registry | not measured: needs verifier | | | |
| timestamp-clustering | not measured: needs verifier | | | |
| verifier-probing | not measured: needs verifier | | | |
| witness-arrival | not measured: needs access-log:witness; verifier | | | |

All attacks together make 0 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### revocation-insider-with-verifiers (insider)

Holds: public, revocation-authority, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | 96 | 1 | 1 | 0 |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 1 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 96 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 96 | 1 | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 96 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 96 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 5.993 bits, 90th percentile 7.725, maximum 8.397.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 5.993, maximum 8.397.

### two-verifiers (colluding-verifier)

Holds: public, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 32 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 16 | 1 | 1 | 0 |
| kel-first-seen | 16 | 1 | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 16 | 1 | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 16 | 1 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 16 joins, precision 1, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 5.993 bits, 90th percentile 7.725, maximum 8.397.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0.5; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0.5; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 5.993, maximum 8.397.

### two-verifiers-terms (colluding-verifier)

Holds: public, verifier:liquor-store, verifier:pharmacy.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs end-role records in a verifier's compartment | | | |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 32 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 16 | not measured | 1 | 0 |
| kel-first-seen | 16 | not measured | 1 | 0 |
| log-scan | 0 | not measured | not measured | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 16 | not measured | 1 | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 0 | not measured | not measured | 0 |
| timestamp-clustering | 16 | not measured | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 16 joins, precision not measured, recall 0. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 4.162 bits, 90th percentile 5.182, maximum 6.065.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0.5; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0.5; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 16; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 4.162, maximum 6.065.

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
