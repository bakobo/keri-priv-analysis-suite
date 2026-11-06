# Privacy analysis report

Scenario `46831a7e582b14ccb67f61ab5aa1bba79d234217888da05bfabe0562791e9d33`, run on the keria adapter with suite 2026.10 and keripy 2.1.0.dev1 (910dcb350e63d3129c91345429c1fa10f2dae5e5). The population has 3500000 rows (seed 1, sha256 `a143ac0841eb99e8313f7908e7e5b97f976647025adbcd96cc1d4f4cc1cf9a3d`).

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
| one-home-hacker | identity_exposed <= 0 | 0 | pass |
| all-homes-hacker | identity_exposed <= 0 | 0 | pass |
| one-home-with-verifiers | reidentified <= 0 | 0 | pass |
| all-homes-with-verifiers | reidentified <= 0 | 0 | pass |
| all-homes-with-verifiers | flagged_domains <= 0 | 2 | fail |
| revocation-insider | identity_exposed <= 0 | 0 | not-measured |
| revocation-insider-with-verifiers | reidentified <= 0 | 0 | not-measured |
| registrar-insider-with-verifiers | reidentified <= 0 | 0 | not-measured |
| observer-insider-with-verifiers | reidentified <= 0 | 0 | not-measured |
| compelled-home | identity_exposed <= 0 | 0 | pass |
| compelled-home-with-verifiers | reidentified <= 0 | 0 | pass |
| registrar-observer-with-verifiers | reidentified <= 0 | 0 | not-measured |
| registrar-observer-with-verifiers | flagged_domains <= 0 | 2 | not-measured |
| hosted-agent-with-verifiers | reidentified <= 0 | 0 | pass |
| hosted-agent-with-verifiers | flagged_domains <= 0 | 2 | fail |

## Failures

many-verifiers: flagged_domains <= 0 fails at 2.
- agent-end-role fails it alone. Cause: keripy bab95c16 src/keri/core/eventing.py:4778 retains each holder AID's agent end role; keria 928ce26a src/keria/app/agenting.py:362 serves the same citizen's AIDs from one agent. Owner: the KERIA hosted-agent operator and SignifyPy holder.
- kel-anchor-adjacency fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:759 anchors each issuance in the issuer's next interaction event, as issued. Owner: SignifyPy issuance and the KERIA issuer.
- kel-first-seen fails it alone. Cause: keripy bab95c16 src/keri/core/eventing.py:3131 stamps each KEL event's first-seen time from the wall clock, and the KEL replay carries it. Owner: KERIA's keripy event store.
- shared-registry fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:735 issues every credential into the issuer's one named registry (status=regk). Owner: SignifyPy issuance and the KERIA issuer's registry policy.
- timestamp-clustering fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:738 stamps the credential and its iss event with the client's clock, to the microsecond. Owner: SignifyPy issuance and the KERIA issuer.

all-homes-with-verifiers: flagged_domains <= 0 fails at 2.
- agent-end-role fails it alone. Cause: keripy bab95c16 src/keri/core/eventing.py:4778 retains each holder AID's agent end role; keria 928ce26a src/keria/app/agenting.py:362 serves the same citizen's AIDs from one agent. Owner: the KERIA hosted-agent operator and SignifyPy holder.
- custodial-join fails it alone. Cause: keripy bab95c16 src/keri/vdr/verifying.py:300 and :305 index every credential by issuer and subject, and keripy bab95c16 src/keri/core/eventing.py:4778 keeps each holder AID's agent end role. Owner: KERIA's credential and agent stores.
- kel-anchor-adjacency fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:759 anchors each issuance in the issuer's next interaction event, as issued. Owner: SignifyPy issuance and the KERIA issuer.
- kel-first-seen fails it alone. Cause: keripy bab95c16 src/keri/core/eventing.py:3131 stamps each KEL event's first-seen time from the wall clock, and the KEL replay carries it. Owner: KERIA's keripy event store.
- shared-registry fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:735 issues every credential into the issuer's one named registry (status=regk). Owner: SignifyPy issuance and the KERIA issuer's registry policy.
- timestamp-clustering fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:738 stamps the credential and its iss event with the client's clock, to the microsecond. Owner: SignifyPy issuance and the KERIA issuer.

hosted-agent-with-verifiers: flagged_domains <= 0 fails at 2.
- agent-end-role fails it alone. Cause: keripy bab95c16 src/keri/core/eventing.py:4778 retains each holder AID's agent end role; keria 928ce26a src/keria/app/agenting.py:362 serves the same citizen's AIDs from one agent. Owner: the KERIA hosted-agent operator and SignifyPy holder.
- hosted-agent fails it alone. Cause: keria 928ce26a src/keria/app/agenting.py:362 boots one agent per controller, serving all of a citizen's AIDs. Owner: the KERIA hosted-agent operator.
- kel-anchor-adjacency fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:759 anchors each issuance in the issuer's next interaction event, as issued. Owner: SignifyPy issuance and the KERIA issuer.
- kel-first-seen fails it alone. Cause: keripy bab95c16 src/keri/core/eventing.py:3131 stamps each KEL event's first-seen time from the wall clock, and the KEL replay carries it. Owner: KERIA's keripy event store.
- shared-registry fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:735 issues every credential into the issuer's one named registry (status=regk). Owner: SignifyPy issuance and the KERIA issuer's registry policy.
- timestamp-clustering fails it alone. Cause: signifypy 2e9772cb signify/app/credentialing.py:738 stamps the credential and its iss event with the client's clock, to the microsecond. Owner: SignifyPy issuance and the KERIA issuer.


## Parties

### all-homes-hacker (hacker)

Holds: issuing-home:0, issuing-home:1, issuing-home:2, issuing-home:3, public.
- issuing-home:0: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- issuing-home:1: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- issuing-home:2: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- issuing-home:3: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.

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
| log-scan | 80 | not measured | 1 | 0 |
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

All attacks together make 80 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### all-homes-with-verifiers (hacker)

Holds: issuing-home:0, issuing-home:1, issuing-home:2, issuing-home:3, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- issuing-home:0: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- issuing-home:1: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- issuing-home:2: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- issuing-home:3: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | 96 | 1 | 1 | 0 |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 144 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 243 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### compelled-home (government)

Holds: issuing-home:0, public.
- issuing-home:0: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.

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
| log-scan | 5 | not measured | 1 | 0 |
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

All attacks together make 5 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### compelled-home-with-verifiers (government)

Holds: issuing-home:0, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- issuing-home:0: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | 6 | 1 | 1 | 0 |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 129 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 228 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### hosted-agent-network (network-observer)

Holds: access-log:hosted-agent, public.
- access-log:hosted-agent: The citizens' wallet host: one KERIA agency hosting one agent per citizen. Its log is what KERIA writes at INFO with request logging on, which records each request's path but not the address it came from, so every line's source is the host's own address. Its records are the agents' own stores.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | not measured: needs verifier | | | |
| batch-order | not measured: needs verifier | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | not measured: needs verifier | | | |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness; verifier | | | |
| holder-kel | not measured: needs verifier | | | |
| hosted-agent | not measured: needs verifier | | | |
| issuer-aid-bucket | not measured: needs verifier | | | |
| kel-anchor-adjacency | not measured: needs verifier | | | |
| kel-first-seen | not measured: needs verifier | | | |
| log-scan | 144 | not measured | 1 | 0 |
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

All attacks together make 144 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### hosted-agent-with-verifiers (network-observer)

Holds: access-log:hosted-agent, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- access-log:hosted-agent: The citizens' wallet host: one KERIA agency hosting one agent per citizen. Its log is what KERIA writes at INFO with request logging on, which records each request's path but not the address it came from, so every line's source is the host's own address. Its records are the agents' own stores.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | 96 | 1 | 1 | 0 |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 208 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 307 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### many-verifiers (colluding-verifier)

Holds: public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 128 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 227 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### many-verifiers-terms (colluding-verifier)

Holds: public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | not measured | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | not measured | 1 | 0 |
| kel-first-seen | 209 | not measured | 1 | 0 |
| log-scan | 128 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | not measured | 1 | 0 |
| timestamp-clustering | 188 | not measured | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 227 joins, precision not measured, recall 0. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0.5; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0.5; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 227; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### observer-insider (insider)

Holds: access-log:observer (absent), public.
- access-log:observer: KERIA has no Observer: a verifier reads TEL state from the issuer's agent through the holder's presentation.

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

### observer-insider-with-verifiers (insider)

Holds: access-log:observer (absent), public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- access-log:observer: KERIA has no Observer: a verifier reads TEL state from the issuer's agent through the holder's presentation.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 128 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 227 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### one-home-hacker (hacker)

Holds: issuing-home:0, public.
- issuing-home:0: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.

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
| log-scan | 5 | not measured | 1 | 0 |
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

All attacks together make 5 joins, precision not measured, recall not measured. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 0 bits, 90th percentile 0, maximum 0.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 0, maximum 0.

### one-home-with-verifiers (hacker)

Holds: issuing-home:0, public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- issuing-home:0: One KERIA agency hosting the issuer's agent: its stores and its log. A credential row's management is the holder's agent AID, read from the end-role record the holder's OOBI left; KERIA has no management AID, and one agent serves all of a citizen's AIDs.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | 6 | 1 | 1 | 0 |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 129 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 228 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### registrar-insider (insider)

Holds: access-log:registrar (absent), public.
- access-log:registrar: KERIA has no Registrar.

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

### registrar-insider-with-verifiers (insider)

Holds: access-log:registrar (absent), public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- access-log:registrar: KERIA has no Registrar.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 128 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 227 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### registrar-observer-network (network-observer)

Holds: access-log:observer (absent), access-log:registrar (absent), public.
- access-log:observer: KERIA has no Observer: a verifier reads TEL state from the issuer's agent through the holder's presentation.
- access-log:registrar: KERIA has no Registrar.

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

### registrar-observer-with-verifiers (network-observer)

Holds: access-log:observer (absent), access-log:registrar (absent), public, verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- access-log:observer: KERIA has no Observer: a verifier reads TEL state from the issuer's agent through the holder's presentation.
- access-log:registrar: KERIA has no Registrar.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 128 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 227 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### revocation-insider (insider)

Holds: public, revocation-authority (absent).
- revocation-authority: KERIA has no revocation authority: the issuer's own agent holds every credential it issued and would revoke it.

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

### revocation-insider-with-verifiers (insider)

Holds: public, revocation-authority (absent), verifier:bar, verifier:clinic, verifier:liquor-store, verifier:pharmacy.
- revocation-authority: KERIA has no revocation authority: the issuer's own agent holds every credential it issued and would revoke it.
- verifier:bar: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:clinic: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 96 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 64 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 96 | 1 | 1 | 0 |
| kel-first-seen | 209 | 1 | 1 | 0 |
| log-scan | 128 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 688 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 688 | 1 | 1 | 0 |
| timestamp-clustering | 188 | 0.923 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 227 joins, precision 0.857, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is mandatory.
Completeness in pharmacy: median 1; citizens with every event in one cluster: 16. Flagged: the party provably holds every event of some citizen in this domain, and use is not mandatory.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### two-verifiers (colluding-verifier)

Holds: public, verifier:liquor-store, verifier:pharmacy.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 16 | 1 | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 32 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 16 | 1 | 1 | 0 |
| kel-first-seen | 45 | 1 | 1 | 0 |
| log-scan | 64 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 164 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 164 | 1 | 1 | 0 |
| timestamp-clustering | 39 | 0.75 | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 82 joins, precision 0.8, recall 1. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0.5; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0.5; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 0; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

### two-verifiers-terms (colluding-verifier)

Holds: public, verifier:liquor-store, verifier:pharmacy.
- verifier:liquor-store: One KERIA agency hosting the verifier's agent: its stores and its log.
- verifier:pharmacy: One KERIA agency hosting the verifier's agent: its stores and its log.

| Attack | Joins | Precision | Certain | Re-identified alone |
|---|---|---|---|---|
| agent-end-role | 16 | not measured | 1 | 0 |
| batch-order | not measured: needs Registrar batches in the public record | | | |
| custodial-join | not measured: needs issuing-home or revocation-authority | | | |
| event-count-lockstep | 0 | not measured | not measured | 0 |
| holder-infrastructure | not measured: needs access-log:mailbox or access-log:holder-witness | | | |
| holder-kel | 0 | not measured | not measured | 0 |
| hosted-agent | not measured: needs access-log:hosted-agent | | | |
| issuer-aid-bucket | 32 observations | not measured | not measured | 0 |
| kel-anchor-adjacency | 16 | not measured | 1 | 0 |
| kel-first-seen | 45 | not measured | 1 | 0 |
| log-scan | 64 | not measured | 1 | 0 |
| payload-invariance | 0 | not measured | not measured | 0 |
| registry-inception-adjacency | 164 | not measured | not measured | 0 |
| registry-reads | not measured: needs access-log:observer or access-log:registrar | | | |
| shared-anchor | 0 | not measured | not measured | 0 |
| shared-batch-root | not measured: needs Registrar batches in the public record | | | |
| shared-holder | 0 | not measured | not measured | 0 |
| shared-registry | 164 | not measured | 1 | 0 |
| timestamp-clustering | 39 | not measured | 1 | 0 |
| verifier-probing | not measured: needs a verifier's own probe log | | | |
| witness-arrival | not measured: needs access-log:witness | | | |

All attacks together make 82 joins, precision not measured, recall 0. Citizens at or above the re-identification threshold of 21.739 bits: 0 of 16; median 6.069 bits, 90th percentile 7.946, maximum 8.417.
Citizens whose legal identity is joined to an identifier issued to them: 0.
Completeness in alcohol: median 0.5; citizens with every event in one cluster: 0.
Completeness in pharmacy: median 0.5; citizens with every event in one cluster: 0.
Joins its accepted terms forbid: 82; a breach of those terms would re-identify 0.
Bits the protocol adds over the party's own context: median 6.069, maximum 8.417.

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
