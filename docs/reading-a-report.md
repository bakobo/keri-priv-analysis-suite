# Reading a report

Each run of a scenario produces one report. The [findings](privacy-findings.md) summarize the scored runs; a report is the evidence behind them. Every party, attack and column heading in a report links to its explanation, and pointing at one shows a short version. This page says what each section of a report is for.

## The heading

The report names the [adapter](glossary.md#adapter-and-generator) that produced the data and the [scenario](glossary.md#scenario) it ran, by its SHA-256 hash. On this site the hash links to the scenario file, which says in its opening comment what it models. The population line says how big the modeled population is, which sets how many [identifying bits](glossary.md#identifying-bits) it takes to single someone out.

## What each adversary learns

One line per [party](glossary.md#party), in plain words. It gives how many [correlations](glossary.md#correlation) the party's attacks made and how many of them were right, how many citizens it can single out of the population, how many legal identities it can attach to what was issued, and for how many citizens it ties every use of one kind together. Proven means at least one of those records rests on certain correlations, so the party could prove that citizen's every use, and every non-use where use is mandatory; not proven means the record may rest on likelihood. Read this section first. A party with confidentiality terms shows how many of its correlations the terms forbid. A party says so when the system under test does not have some of its data, or when the adapter could not export it.

## Claims

The claims the scenario stated before the run, one row each: the party, the claim in words, the number measured, and the [verdict](glossary.md#claim-and-verdict). A claim fails when the measured number exceeds what the claim allows. Not measured means the party lacked what the claim needs, which is never the same as holding.

## Why claims fail

For each failing claim, every attack that would make it fail on its own, with the cause and the owner. The cause usually names a line of code in the system under test, at the commit that ran. The owner is the component or team that would have to change it. When no single attack fails a claim, the report says that the attacks fail it only in combination.

## Measurement limits

What the measurement cannot see, such as identifying bits that are a lower bound because the presented bytes say more than the attribute they declare.

## Parties

One section per party. It says what kind of adversary the party is and which [compartments](glossary.md#compartment) it holds, and what the adapter put in each. Then comes a table with one row per [attack](attacks.md):

- Correlations: how many links this attack made on its own. An attack that adds identifying bits without linking anything, such as which issuing server signed, shows observations instead.
- [Precision](glossary.md#precision): the share of those links that are right.
- [Certain](glossary.md#certain): the share resting on proof rather than likelihood.
- Re-identified alone: citizens this attack singles out without help from the others.
- Not measured, with what was missing, when the party does not hold what the attack reads.

Below the table, the totals for all attacks together: correlations, precision, [recall](glossary.md#recall), the spread of identifying bits across citizens against the re-identification threshold, legal identities attached, [completeness](glossary.md#completeness) for each kind of use, correlations its terms forbid, and the [protocol increment](glossary.md#protocol-increment).

## The end of every report

Two lists close every report. The first is attacks the catalogue does not make yet, so silence on those channels is not a result. The second is what the suite does not claim at all, such as resistance to an adversary who can watch the whole internet.
