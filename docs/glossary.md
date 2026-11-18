# Glossary

These are the words the reports and the findings use, in plain terms. The reports link each word here, and pointing at a linked word shows its one-sentence version.

## The setting

### Citizen and population

A citizen is a simulated person who holds credentials issued by the State. Each scored run has 16 simulated citizens, drawn from a modeled population of 3.5 million people with realistic attributes such as age band and county. The population is what makes identifying bits meaningful: it says how many people share each attribute.

### Credential and presentation

A credential is a signed statement the State issues to a citizen, such as proof of age. The State issues each citizen several copies so that each use can show a different copy. A presentation is one use of a credential: the citizen shows a copy to a verifier, which checks it.

### Verifier

A business or office that checks credentials, such as a liquor store, a pharmacy, a bar or a clinic. Each keeps a record of the presentations it received.

### Issuing home

One of the State's servers that issue credentials. The scored runs model four. Each holds what it needs to issue and revoke, which can include which credential went to which citizen.

### Public record

What anyone can read: each issuer's key event log, each credential registry's log, and any published batches. A credential's validity is checked against it, so every verifier reads it too.

### Compartment

One body of stored data behind one access boundary, such as one verifier's records or one issuing home's database. Whoever breaks one boundary, by a breach, an insider's credentials or a legal demand, gets the whole compartment at once.

### Party

An adversary, described by the compartments it holds. Colluding verifiers pool their records; a hacker or insider holds State compartments; another government office compels records; a network observer reads service logs. Each report has a section per party.

### Confidentiality terms

Terms a verifier can accept that forbid it to correlate what it receives. Correlations that terms forbid are counted apart from the harm totals, as what a breach of the terms would expose. Terms never bind a government office that compels disclosure.

### Scenario

A file that fixes everything a run depends on: the population, the citizens and their credentials, the verifiers, the parties, the stack's settings, and the claims. Its SHA-256 hash, shown at the top of each report, identifies it exactly; on this site the hash links to the file.

### Adapter and generator

An adapter connects the suite to one implementation and hands over what each compartment holds. The generator is an adapter that builds that data from settings instead of running a real stack, so designs that are not built yet can be scored. The KERIA adapter runs real KERIA agents driven by SignifyPy.

## What the suite measures

### Attack

One way of correlating. An attack reads only what a party holds, never a running system and never the answer key. Each attack first proves on a test setup that it does find a link where one exists, and finds none where none exists, before its silence on a real run counts for anything. The [attacks page](attacks.md) lists them all.

### Correlation vector

One of the five routes by which a deployment's mitigations were expected to be attacked: shared registries, timestamps, batches, identifiers (AIDs), and network observation. Each attack tests one or more of them.

### Correlation

A link an attack makes between two things a party holds, such as two presentations, two identifiers, or a presentation and a legal identity, asserting that they belong to the same citizen. Reports count them per attack and for all attacks together. The data files call them joins.

### Certain

The share of an attack's correlations that rest on proof, such as two presentations carrying the same identifier, rather than on likelihood, such as two timestamps a few milliseconds apart. A certain correlation lets the party prove that a citizen did something.

### Precision

Of the correlations an attack made, the share that are correct, judged against the run's answer key. 1 means none was wrong. Below 1, the attack sometimes ties two different citizens together.

### Recall

Of the correlations that could have been made, the share the attacks made.

### Identifying bits

How much a party's correlated data narrows down who a citizen is. Each bit halves the number of people who fit: 1 bit leaves half the population, 10 bits about one in a thousand. Correlating two presentations that disclose different attributes, an age band at one shop and a county at another, adds their bits together. A wrong correlation adds nothing, because it would attach someone else's attribute.

### Re-identified

A citizen about whom a party gathers enough identifying bits to single them out of the whole population. For 3.5 million people that takes log2(3,500,000), about 21.74 bits; the report calls this the re-identification threshold. A party that also holds a citizen's legal identity re-identifies them outright.

### Completeness

For one kind of credential use, such as alcohol purchases, the share of a citizen's uses that a party has tied together. When it reaches 1 with certain correlations, the party holds proof of every such use by that citizen, and when use is mandatory, proof of every time they did not buy, too.

### Flagged domain

A kind of credential use in which a party reaches complete, certain coverage of at least one citizen. The alcohol domain is mandatory in the scored scenarios and pharmacy is optional; a report says which.

### Protocol increment

The identifying bits the protocol adds beyond what a party already knows from its own context. A shop sees a customer's face and card; the scored runs set that context to zero bits so that what the protocol leaks stands out. For State compartments the context is always zero.

## Reading the outcome

### Claim and verdict

A claim is a statement about one party, written into the scenario before anything was run, such as "four colluding verifiers re-identify no citizen". Its verdict is holds, fails, or not measured. Thresholds are never moved after a run; a failed claim is a finding.

### Not measured

The party lacks something the claim or attack needs, usually because the stack under test has no such component (KERIA has no Registrar, for example). Not measured never means safe: the attack had nothing to read.

### Cause and owner

For each attack that makes a claim fail on its own, the report names the cause, usually a line of code in the stack, and the owner, the component or team that would have to change it.
