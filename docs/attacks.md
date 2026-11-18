# Attacks

Each attack is one way an adversary can correlate what it holds. An attack reads only a party's compartments, never a running system and never the answer key, and each first proves on a test setup that it finds a link where one exists and none where none does. A report lists, for each party, what every attack found. This page is generated from the catalogue by `scripts/attacks-page`; do not edit it by hand.

## Agent named in the holder's records (agent-end-role)

Checking a holder identifier tells the verifier which agent serves it. One agent serves all of a citizen's identifiers, so naming the same agent ties them together.

It needs a verifier's records. It tests the AID and network [correlation vectors](glossary.md#correlation-vector).

## Correlations copied into logs (log-scan)

Logs that write two identifiers on one line, or tag related lines with one request or session id, tie together whatever they name. This attack searches every log a party holds.

It needs the public record or a verifier's records or an issuing home or the orchestrator's store or the issuer's operation log or the revocation authority's records or the identity-proofing records or an access log. It tests the registry, timestamp, batch, AID and network [correlation vectors](glossary.md#correlation-vector).

## First-seen times in the issuer's log (kel-first-seen)

The issuer's public log carries the time each entry was first seen, from a server clock, untouched by any coarsening of the registry times. One citizen's issuances cluster in time.

It needs the public record; and a verifier's records. It tests the timestamp [correlation vector](glossary.md#correlation-vector).

## Neighbouring issuance anchors (kel-anchor-adjacency)

Each issuance is recorded in order in the issuer's public key event log. When one citizen's copies are issued one after another, their records sit next to each other, which ties them together.

It needs the public record; and a verifier's records. It tests the batch and AID [correlation vectors](glossary.md#correlation-vector).

## Neighbouring registry creations (registry-inception-adjacency)

Registries created in a batch and handed out in order give one citizen registries created next to each other in the issuer's public log, which ties that citizen's credentials together.

It needs the public record; and a verifier's records. It tests the registry [correlation vector](glossary.md#correlation-vector).

## One hosted agent per citizen (hosted-agent)

A cloud agent that runs a citizen's wallet sees all of that citizen's traffic, so its host's logs tie together every identifier it serves.

It needs the hosted-agent service's access log; and a verifier's records. It tests the network [correlation vector](glossary.md#correlation-vector).

## One identifier for every copy (shared-holder)

A wallet that presents every copy under the same identifier ties them all together. This is KERIA's ordinary usage.

It needs a verifier's records. It tests the AID [correlation vector](glossary.md#correlation-vector).

## Order inside a published batch (batch-order)

A batch that mixes citizens but lists credentials in the order they were issued keeps each citizen's copies next to each other.

It needs the public record; and a verifier's records. It tests the batch [correlation vector](glossary.md#correlation-vector).

## Reading the State's stored map (custodial-join)

The issuing home or revocation authority keeps a map from each credential to the citizen's identifier, and from there to a legal identity. Whoever holds it reads the correlation directly.

It needs an issuing home or the revocation authority's records. It tests the registry, timestamp, batch, AID and network [correlation vectors](glossary.md#correlation-vector).

## Recorded in one log entry (shared-anchor)

An issuer that records several of one citizen's registries or issuances in a single entry of its public log ties them together for everyone who reads it.

It needs the public record; and a verifier's records. It tests the batch and registry [correlation vectors](glossary.md#correlation-vector).

## Registries that change together (event-count-lockstep)

Registries whose update counts rise together, because one citizen's registries are updated in the same step, are tied together by those counts alone.

It needs the public record; and a verifier's records. It tests the registry [correlation vector](glossary.md#correlation-vector).

## Registry reads in access logs (registry-reads)

The services that publish credential status log who asked about which registry, when, and from where. A wallet checking its own credentials from one address ties them together.

It needs the Observer's access log or the Registrar's access log; and a verifier's records. It tests the network [correlation vector](glossary.md#correlation-vector).

## Shared batch commitment (shared-batch-root)

When credentials are published in signed batches, two credentials under the same batch are tied together, and a batch that holds only one citizen's credentials gives them all away. Only the generator models batches today.

It needs the public record; and a verifier's records. It tests the batch [correlation vector](glossary.md#correlation-vector).

## Shared delegator or witnesses (holder-kel)

A verifier must read a holder identifier's key event log to check a presentation. Identifiers that name the same delegator, or the same witnesses, are tied together.

It needs a verifier's records. It tests the AID [correlation vector](glossary.md#correlation-vector).

## Shared registry (shared-registry)

Two presented credentials that point to the same registry, the public list that records whether each credential is still valid. An issuer that puts a citizen's credentials in one registry ties them together for anyone who reads it.

It needs the public record; and a verifier's records. It tests the registry [correlation vector](glossary.md#correlation-vector).

## Shared wallet infrastructure (holder-infrastructure)

A fresh identifier per copy does not help when every copy's identifier is registered with the same mailbox and witnesses, from the same network address.

It needs the mailbox service's access log or the holder witnesses' access log; and a verifier's records. It tests the AID and network [correlation vectors](glossary.md#correlation-vector).

## Timestamp clustering (timestamp-clustering)

Every credential's registry entry carries the time it was issued, to the microsecond. One citizen's copies are issued milliseconds apart, so their times stand out as a cluster.

It needs the public record; and a verifier's records. It tests the timestamp [correlation vector](glossary.md#correlation-vector).

## Values a fresh copy should not repeat (payload-invariance)

Presented credentials that share a value a fresh copy would make unique, such as a cloned block of attributes or a reused salt.

It needs a verifier's records. It tests the AID and registry [correlation vectors](glossary.md#correlation-vector).

## Verifier probing (verifier-probing)

A verifier that polls the public registry feed itself learns when each registry first appeared. Registries that appeared together were issued together.

It needs a verifier's records. It tests the network [correlation vector](glossary.md#correlation-vector).

## When the witnesses received each entry (witness-arrival)

The State's witnesses log when each issuer log entry arrived. That clock time ties a citizen's issuances together even when the registry times are coarsened.

It needs the witnesses' access log; and the public record; and a verifier's records. It tests the timestamp and network [correlation vectors](glossary.md#correlation-vector).

## Which issuing home signed (issuer-aid-bucket)

A presentation shows which of the State's issuing homes signed it. That does not tie presentations together, but it narrows down who the citizen is by about log2 N bits for N homes, more if homes serve particular regions.

It needs a verifier's records. It tests the AID [correlation vector](glossary.md#correlation-vector).
