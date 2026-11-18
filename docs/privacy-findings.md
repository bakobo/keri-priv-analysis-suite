# What the scored runs found

The suite simulated 16 citizens who each received four copies of an age credential from the State and used them four times, at four businesses: twice to buy alcohol, where showing the credential is mandatory, and twice for pharmacy purchases, where it is optional. It then asked, for each kind of adversary that might get hold of some of the resulting data: what could that adversary work out about those citizens?

It asked this of two systems. The first is a design model, the [generator](glossary.md#adapter-and-generator), set up like a custodial issuer that keeps one registry per credential, hands registries out in order, issues each citizen's copies together, and keeps a named copy of each credential it issued. The second is KERIA, real KERI agent software, driven by SignifyPy and run as it is ordinarily used. Every claim below was written down before either run, and none was changed afterwards.

## The short answer

- Shops that compare their records cannot work out who a customer is from the credentials alone, on either system. But four shops together can prove which purchases belong to the same person, and they do so for every alcohol purchase of all 16 citizens. Because showing the credential is mandatory for alcohol, that is a complete record of who bought and who did not.
- Confidentiality terms that forbid the shops to compare records do not stop the comparison. They make it a breach, which is all they can do.
- On the design model, a hacker who breaks into the State's issuing servers learns the legal identity of every citizen those servers issued to, because the servers keep a named copy of each credential. With the shops' records as well, the hacker identifies all 16 citizens outright. On KERIA, the issuing servers hold no legal identities in this setup, so the same break-in exposes none.
- On KERIA, someone who can read the logs of the service that runs citizens' cloud wallets can tie together all of each citizen's identifiers.
- Several State systems that KERIA does not have, such as a separate revocation authority, a Registrar or an Observer, could not be measured on KERIA. That is not a pass.

## Each adversary, answered

Each answer links to the part of a report that shows it. "Re-identify" means gathering enough about a citizen to single them out of a population of 3.5 million, which takes about 21.7 [identifying bits](glossary.md#identifying-bits).

| Question | Design model | KERIA |
|---|---|---|
| Can two shops that compare records identify a customer? | No. They tie 16 pairs of purchases together, but learn only about 6 of the 21.7 bits needed ([report](../results/privacy-generator-baseline/report.md#two-colluding-verifiers-two-verifiers)). | No. They tie 82 pairs together, a few of them wrongly, and learn about 6 bits ([report](../results/privacy-keria-baseline/report.md#two-colluding-verifiers-two-verifiers)). |
| Can four shops that compare records identify a customer? | No: about 6 bits each ([report](../results/privacy-generator-baseline/report.md#four-colluding-verifiers-many-verifiers)). | No: about 6 bits each ([report](../results/privacy-keria-baseline/report.md#four-colluding-verifiers-many-verifiers)). |
| Can four shops prove they hold every alcohol purchase a customer made? | Yes, for all 16 citizens, and every pharmacy purchase too. This claim fails. | Yes, for all 16 citizens, and every pharmacy purchase too. This claim fails. |
| Do confidentiality terms stop that? | The correlations still exist; the terms make using them a breach ([report](../results/privacy-generator-baseline/report.md#four-colluding-verifiers-bound-by-confidentiality-terms-many-verifiers-terms)). | The same ([report](../results/privacy-keria-baseline/report.md#four-colluding-verifiers-bound-by-confidentiality-terms-many-verifiers-terms)). |
| Can a hacker who breaks into one issuing server learn who citizens are? | Yes, the one citizen that server issued to. This claim fails ([report](../results/privacy-generator-baseline/report.md#a-hacker-who-breaks-into-one-issuing-home-one-home-hacker)). | No: it holds no legal identity ([report](../results/privacy-keria-baseline/report.md#a-hacker-who-breaks-into-one-issuing-home-one-home-hacker)). |
| Can a hacker who breaks into every issuing server learn who citizens are? | Yes, all 16. This claim fails ([report](../results/privacy-generator-baseline/report.md#a-hacker-who-breaks-into-every-issuing-home-all-homes-hacker)). | No ([report](../results/privacy-keria-baseline/report.md#a-hacker-who-breaks-into-every-issuing-home-all-homes-hacker)). |
| ... and with the shops' records too? | It identifies all 16 outright and holds their complete purchase records. Both claims fail ([report](../results/privacy-generator-baseline/report.md#a-hacker-in-every-issuing-home-with-the-verifiers-records-all-homes-with-verifiers)). | It identifies no one, but holds every citizen's complete alcohol record. That claim fails ([report](../results/privacy-keria-baseline/report.md#a-hacker-in-every-issuing-home-with-the-verifiers-records-all-homes-with-verifiers)). |
| Can another government office that compels one server's records ten years later learn who citizens are? | Yes, that server's one citizen, because its records were kept forever. This claim fails ([report](../results/privacy-generator-baseline/report.md#another-government-office-that-compels-one-issuing-homes-records-ten-years-on-compelled-home)). | No ([report](../results/privacy-keria-baseline/report.md#another-government-office-that-compels-one-issuing-homes-records-ten-years-on-compelled-home)). |
| Can an insider at the revocation authority learn who citizens are? | No ([report](../results/privacy-generator-baseline/report.md#a-malicious-insider-at-the-revocation-authority-revocation-insider)). | Not measured: KERIA has no separate revocation authority; the issuer's own server, measured above, holds what it would. |
| Can someone reading the cloud-wallet service's logs tie a citizen's identifiers together? | Not in this setup, which has no cloud wallets; a [separate run](../results/privacy-generator-network/report.md#a-network-observer-at-the-hosted-agent-service-hosted-agent-network) that adds them shows that it can. | Yes, all of them. With the shops' records it also holds every citizen's complete alcohol record; that claim fails ([report](../results/privacy-keria-baseline/report.md#a-hosted-agent-network-observer-with-the-verifiers-records-hosted-agent-with-verifiers)). |
| Can someone reading the Registrar's or Observer's logs tie a citizen's credentials together? | No, on both design-model runs ([report](../results/privacy-generator-baseline/report.md#a-network-observer-at-the-registrar-and-observer-registrar-observer-network)). | Not measured: KERIA has neither service. |

## Why it happens

On both systems the shops' correlations come from what the issuer publishes and how it issues, not from anything the citizen shows. One citizen's copies are issued one after another, so their records sit next to each other in the issuer's public log, and the times stamped on them cluster to within milliseconds. On KERIA, every credential also goes into one shared registry, and every identifier a citizen uses names the same cloud agent. The [attacks page](attacks.md) explains each of these, and each report names the line of code responsible and who would have to change it.

## What would help, on the design model

The [countermeasure sweep](../results/privacy-sweeps/README.md) changed one setting at a time on the design model and reran everything. Handing out registries at random weakened the attack it targets sharply, but other correlations still tied every citizen's alcohol purchases together. Mixing the order in which different citizens' copies are issued did more: four shops then held a complete alcohol record for 3 citizens instead of 16. Coarsening the time stamps alone, or delaying publication, changed nothing, because the ordering in the public log remained. Keeping the issuing servers' records for a year rather than forever stopped the ten-year disclosure but not a theft within the year. Giving each issuing server only a per-agency pseudonym instead of a name removed the legal identities a break-in exposed. These are results for a model, not for a system that has been changed; a system that adopts a countermeasure needs its own run.

## How far to trust this

The 16 citizens show that each attack works and how much it yields; they do not estimate how often something would happen across a real population. The design-model runs are deterministic: rerunning a scenario reproduces it exactly. KERIA's time stamps come from the real clock, so a rerun gives the same verdicts but some timing-based counts can move; that is why a few of KERIA's correlations tie different citizens together. A shop's identifying bits are a lower bound wherever the bytes it receives say more than the attribute they declare, such as a full birth date behind an age band. Attacks the catalogue does not make yet are listed at the end of every report.

## The evidence

| Run | What it is |
|---|---|
| [Design model](../results/privacy-generator-baseline/report.md) | The generator, set up as a custodial issuer, with all the adversaries above. |
| [Design model with cloud wallets](../results/privacy-generator-network/report.md) | The same, plus a cloud agent per citizen and wallets that check their own credentials' status, so the network-observer attacks have something to find. |
| [KERIA](../results/privacy-keria-baseline/report.md) | Real KERIA agents driven by SignifyPy, four issuing servers, the same adversaries. |
| [Countermeasure sweep](../results/privacy-sweeps/README.md) | 35 runs of the design model, each changing one setting. |

[Reading a report](reading-a-report.md) explains what a report contains. The complete run directories are kept outside Git and bound to these reports by a [SHA-256 manifest](../results/raw-exports.sha256).
