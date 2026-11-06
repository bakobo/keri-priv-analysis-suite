# keri-priv-analysis-suite — Intent Tree (this.i)
#
# Source of truth for this repo's intentions and the decisions that follow from them. Each
# consequential decision is recorded here, in its own commit, before the code that implements it.
# Ids are minted by `i id` and never typed.
#
# Origin: a design review held 2026-10-14 to 2026-10-16 for a state digital-identity deployment.
# Its record cites private correspondence and is not part of this repository.

Measure what a KERI/ACDC deployment lets each adversary join about a citizen, on any implementation = goal:
  nid: 34te7g4t
  why: >-
    A deployment that issues bulk ACDC copies to citizens relies on mitigations (one registry per credential, a fresh holder AID per copy, unique nonces) to keep two verifiers who compare notes from linking a citizen's presentations, and needs to show those mitigations work against registry, timestamp, batch, AID and network-observation correlation. Nobody had attacked them, and reading a custodial issuer's source during the design review predicted at least two leaks (KEL adjacency of a citizen's copies, microsecond `dt` on every blinded TEL event) that link a citizen's bulk copies. Chose a stack-agnostic suite in its own repo, beside keri-conformance-suite, over attack tests inside the issuer, because the same instrument must rerun against KERIA or any other stack, and a privacy verdict produced by the vendor's own tests is weak evidence. Tradeoff: an adapter layer that in-repo tests would not need.
  children:
    Adversaries are parties, and colluding verifiers and parties who obtain State data are co-equal = decision:
      nid: 23c7h5vs
      why: >-
        Most readers, and most of KERI's own privacy writing, frame the threat as colluding verifiers. That is a major concern, but a dangerous oversimplification when it stops there. The State holds a legally required join between legal identity and every identifier and salt it issued, so whoever obtains that join can unblind presentations. "The State" is not one party, and talking about it as one defeats reasoning about the threat. So the adversaries are parties: verifiers who pool what they receive (second parties), and, for data the State holds, a hacker, a malicious insider, or another part of government that compels disclosure. The design review judged that set fairly complete. Rejected treating the State as trusted (it loses every custodial risk) and as one hostile adversary (every claim then fails trivially and the measurement says nothing). The catalogue starts with verifier collusion, where readers start, and extends the same machinery to State data, so results answer the common lens and show where it stops. Tradeoff: many more scenarios than a single adversary model.
      children:
        A compartment is a body of stored data behind one access boundary = decision:
          nid: 9hztf0uy
          why: >-
            What an adversary obtains is defined by access, not by organisation: a single event (one breach, one insider's credentials, one legal demand on its custodian) exposes all of a compartment together. Two stores one administrator can read together are one compartment. The term was defined in the design review because undefined coined terms were obscuring the threat model. Every compartment the deployment creates or touches is in scope, including the issuing home's pool table (registry to credential SAID to holder AID), the orchestrator store, an asynchronous issuer's operation log, the revocation authority, identity proofing records, witness, Registrar and Observer operators, hosted agents, and each verifier. Rejected exempting the issuer's own records as an inherent non-claim: the join's existence is a design premise, but how it is held, for how long and beside what is measurable and changeable. Tradeoff: an adapter must expose each compartment's contents, which a stack may not make easy.
        Logs are compartments, and retention is a measured parameter = decision:
          nid: 4ww9snv2
          why: >-
            Lax IT and careless logging are as likely a route to the join as the database itself, and issuers already log registry ids. Laws change and the architecture does not move with them, so the suite assumes a compartment is obtained later, by a party who gets everything it retained. Each compartment's retention is therefore an input, and expiry or sealing is a configuration the suite scores. Rejected scanning only primary stores, because a log that copies a join defeats every protection of the store. Tradeoff: log adapters for every component.
        The network adversary is a passive observer of infrastructure logs, plus probing a participant could do = decision:
          nid: 5y304fhq
          why: >-
            Network observation is measured from the access logs that witness, Registrar, Observer, watcher and agent hosts keep, which every adapter can supply, plus active probing only where a participant can act anyway (a verifier timing its own queries). A global passive adversary is a stated non-claim, and there is no packet capture. Rejected lab packet capture: it would catch transport-level leaks such as TLS fingerprints at roughly double the cost, and those leaks are not KERI's.
    Harm is accumulated identifying bits, never "unlinkability" = decision:
      nid: 8q5ylk4q
      why: >-
        A join between presentations matters in proportion to what it adds. Joining presentations that disclose the same attributes adds little beyond a sequence of times; joining presentations that disclose different attributes accumulates them, as in the EFF information-theory primer (Eckersley, 2010). So harm is measured in identifying bits per simulated citizen, against a re-identification threshold set by the population searched (about 22 bits for a population of 3.5 million; the population model is an input). Results never claim "unlinkability": they state joins, bits and cost. Rejected a pass/fail claim that no catalogued attack links two presentations, because it cannot say how close an attack came, and because a join of identical disclosures is not where the danger lies. Tradeoff: an attribute and population model the suite must carry and justify.
      children:
        A join forbidden by terms that bite is reported apart, as a breach the party would have to commit = decision:
          nid: 2leqqwzy
          why: >-
            Harm counts only what a join adds where no legal anti-correlation measure binds its maker. A hacker does not care about legalities, so everything stolen is combinable. A verifier that accepted chain-link confidentiality terms for safe harbor (Hartzog 2012; keripy test_cp_disclosure.py, an Assimilation clause accepted by a signed IPEX agree) is forbidden to correlate, and its breach would leave evidence. So each join is labelled by whether its maker is bound, and bound joins are excluded from the harm total and reported separately. Rejected counting every technically possible join, which overstates verifier harm, and ignoring them, which hides what a terms breach would expose. A government party compelling disclosure may override terms, so it is never treated as bound. Tradeoff: the scenario must say which terms each party accepted.
        Precision and completeness are reported beside bits = decision:
          nid: 4wrq8j56
          why: >-
            A certain join (a shared identifier) lets an adversary prove use or non-use, and a probabilistic one does not, so precision is reported. Worse than many proven events is proof that every event of a kind is in the dataset. Completeness is the share of a citizen's events in a domain (alcohol purchases, say) that the adversary's joined set holds. It becomes total when credential use is mandatory for the domain and joins are certain; then the dataset proves absence as well as presence. Mandatory use is policy, not protocol, so it is a scenario parameter, and any domain reaching total completeness is flagged. Tradeoff: scenarios need event domains, not only presentations.
        Measure only the linkage the protocol adds beyond a compartment's own context = decision:
          nid: 3tvy0xj4
          why: >-
            A verifier controls its presentation context (address, fingerprint, location, payment) and can often re-identify a presenter from that alone, so cryptographic unlinkability holds only in narrow conditions. That critique stops at State compartments: an issuing home, a revocation authority or a log never sees presentation context, so every join it makes comes from the protocol. The suite therefore reports, per party, the joins the protocol adds over that party's own context, which is zero for State compartments. Re-identification from behavioural quasi-identifiers alone (the same pharmacy every Tuesday) is a stated non-claim. Disclosed attributes are not a linkage vector the suite attacks, since limiting them is graduated disclosure's job, but they are what the bits model sums. Tradeoff: a verifier result reads as "the protocol is not the weakest link", which is a weaker headline.
        ? A citizen's bits count only what a party attributes to them correctly, over clusters holding their presentations = decision
        : nid: 08cl03nc
          why: >-
            For each cluster a party forms that holds at least one of a citizen's presentations, the scorer takes the attributes disclosed in that citizen's own presentations in the cluster, plus any attribute an attack observed on them whose value is the citizen's true one, and scores log2(P/m); a cluster that also holds the citizen's legal identity scores log2(P). The citizen's bits are the maximum over such clusters. A false join adds nothing, because the party would hold another person's attribute, which misleads it rather than exposing the citizen; it still costs the attack precision, which is reported. A cluster of identity records and identifiers with no presentation measures custodial exposure, not activity, so it is counted separately as citizens whose legal identity the party joins to an issued identifier, rather than scored as full re-identification for every row of an identity database the party simply holds. Completeness is flagged only for a citizen with at least two events in the domain, since one event held alone is trivially complete. A join is bound when the party is not a government party and either end is a presentation from a compartment whose holder accepted terms. The protocol increment is the party's bits less the context bits it declares, floored at zero. Rejected counting every attribute in a cluster, which credits a party for confusing two people. Tradeoff: an adversary that acts on wrong joins can still harm a citizen, and that harm is outside these numbers.
    Every attack proves it can find a link before its silence counts = decision:
      nid: 97nt9ugu
      why: >-
        Each attack ships with a positive control, a configuration built so the vector leaks, which the attack must link with precision 1.0, and a negative control built so the vector does not leak, on which it must score at chance. Without the first, "found no link" cannot be told from "the attack is broken"; an earlier demonstration harness had exactly that failure, checking two copies of five and passing with fewer grants than requested. "Positive control" is borrowed from experimental science, not coined. Tradeoff: two extra configurations per attack.
    Independent of any stack, including Bakobo's = goal:
      nid: 4c49xc2c
      why: >-
        A third party must be able to rerun the suite against any implementation, so Bakobo is not grading its own homework. The four parts below make that possible. Tradeoff: the cost of a second adapter and of public scrutiny of results that will not be clean.
      children:
        Attacks read only bytes and logs a party could hold, never a stack's API = decision:
          nid: 364eng34
          why: >-
            An adapter drives issuance and presentation and hands over each compartment's contents as CESR bytes, records and logs, plus ground truth for scoring. Attacks see only compartment contents. Rejected attacks that query a stack, because they would test what the stack exposes to the suite, not what a party holds, and would need rewriting per stack. Tradeoff: an adapter must serialize stores that were never meant to be exported.
          children:
            A compartment holds four kinds of content, and ground truth travels separately = decision:
              nid: 9wxr29dq
              why: >-
                An adapter hands over each compartment as a name from a closed vocabulary (the public record, a verifier, an issuing home, the revocation authority, identity proofing, an operator's access logs, and so on), a status of present, absent or not measured, and contents of four kinds only: CESR streams (a KEL, each TEL, Registrar batches), record tables (rows of named fields, such as an issuing home's pool table), log lines (time, source address, raw text), and presentations (an opaque handle, the verifier, the time, the disclosed attributes, the event domain and the presented bytes). Ground truth, which maps each presentation handle and each legal-identity record to a simulated citizen, is a separate object written to its own file in the run directory; attacks are given compartments loaded from the run directory's compartment files and nothing else, so the isolation test can prove they never see the answer. Rejected letting attacks read each stack's native stores (LMDB, sqlite), because every attack would need a parser per stack and that is the coupling 364eng34 exists to avoid. Rejected one opaque blob per compartment, because each attack would then parse heterogeneous formats. Tradeoff: an adapter must translate stores into rows, and a translation can drop join material; logs therefore keep each raw line, and the contract suite checks that every identifier in a compartment refers to an artifact the adapter issued.
        Two adapters ship first, a custodial issuer and KERIA with Signify, against one contract suite = decision:
          nid: 97h32zrn
          why: >-
            One adapter cannot show the interface is stack-agnostic. KERIA's ordinary usage issues many credentials into one registry, so it is also a natural positive control for the registry attack. Rejected the custodial issuer only, with a documented interface, which leaves stack independence unproven until a stranger writes the second adapter. Tradeoff: unmeasured cost of the KERIA adapter, guessed at two days.
          children:
            The public repository holds the suite, the generator and the KERIA adapter; the custodial-issuer adapter stays private = decision:
              nid: 6vk37hwt
              why: >-
                The custodial-issuer stack the suite was first run against depends on private repositories, so its adapter cannot be built from a fresh clone without a credential, and it vendors schemas and deployment rules that are not ours to publish. The public tree therefore starts from the root suite, the synthetic generator and the KERIA adapter, whose whole dependency closure is public, and that adapter stays in a private companion repository that depends on this one. Rejected publishing it with its dependencies stubbed, which would ship an adapter nobody can run, and waiting for the stack to be published, which would hold the instrument hostage to an unrelated release. Tradeoff: a reader can rerun the generator and KERIA results but not the custodial-issuer ones, and the generator-fidelity test (docs/test-plan.md, Part B item 6) runs only where that adapter is.
              children:
                The vendored schemas and deployment rules were dropped with the adapter, not stubbed = decision:
                  nid: 6h7k9kyr
                  why: >-
                    The custodial-issuer adapter carried copies of its deployment's credential schemas and rules, which only it read. Nothing in the root suite, the generator or the KERIA adapter loads them, so they and the tests that used them left with the adapter, and nothing here fetches them. Rejected a stub that fetches them at test time, which would need the same credential the adapter does. Tradeoff: none in this tree; the private adapter keeps them.
        A synthetic generator is an adapter, so designs are scored before they are built = decision:
          nid: 8zuzm3v3
          why: >-
            The cheapest leaks to fix are in designs nobody has built: batch commitment, pool allocation, Registrar batch windows, fleet size N across issuing homes (about log2 N bits per presentation). Because attacks read only compartment contents, a generator that emits real KEL and TEL bytes from parameters, using keripy directly and no witnesses, is just another adapter. Its output is curves (bits against batch window, say) handed to whoever builds those features. Rejected testing only running stacks, which lets those features discover their leaks after they ship. Tradeoff: the generator must be shown to match a real adapter, attack for attack.
          children:
            Declare evidence the generator does not model as an exact fidelity difference = decision:
              nid: 8ps45j4u
              why: >-
                An asynchronous custodial issuer retains a durable operation log, and the generator explicitly does not model one. A live fidelity run found exactly two new log-scan verdicts for home-holding parties, with every other attack verdict still matching. A fidelity test that demanded equality on this known unequal evidence would either force invented operation rows into every predeclared generator sweep or conceal the real asynchronous leak. Instead, the test requires the exact documented differences and keeps all other verdict, claim, bits and re-identification comparisons strict. If a difference disappears or a new one arises, the test fails and the cause must be investigated.
        Other labs red-team the catalogue, and the repo is public before results are delivered = decision:
          nid: 40ftzf89
          why: >-
            Models from other labs try to break or extend the attack catalogue before the first scored run, because the author of a catalogue is the worst judge of what it misses. The repo is made public before any result is delivered, so the claim can be checked by someone who is not us. Rejected publishing results without the code, which asks for trust the item exists to replace. Tradeoff: the first public results will show leaks in Bakobo's own stack.
        Nothing private is ever committed here = constraint:
          nid: 92hxgvkz
          why: >-
            The design review drew on private correspondence and on internal plan records. This repo is public, so it never vendors, quotes or summarizes their private content. Review-panel output goes to a private review archive rather than into this tree. Published sources (the EFF primer, Hartzog's paper, keripy) may be cited and vendored with provenance.
    Countermeasures are scored as configurations, including ones not yet built = decision:
      nid: 2gxskju4
      why: >-
        Each countermeasure that changes what a compartment holds or publishes is a scenario parameter the suite can turn on and score before and after: random registry allocation (it fixes only the inception half of KEL adjacency), mixing issuance order across citizens and coarse `dt` (requirements on an asynchronous issuer, a fleet orchestrator and batch commitment), an identity oracle that gives each agency only its own cryptonym, decoy registries and records, a revocation map sealed away from the issuing home, and retention expiry. The list was adopted provisionally in the design review, to be revisited as results arrive. Social recovery and permuted photos are out, because neither changes linkage and face recognition re-links photos. Breach detection by canaries is a different property and a separate item. Tradeoff: the generator must model countermeasures that no stack implements yet.
      children:
        A sealed revocation map leaves named retained credentials visible at the home = decision:
          nid: 7wwc4pdd
          why: >-
            The first live smoke run of a custodial issuer exposed clear given name, family name and birth date in every credential the issuing home retains, beyond its pool's revocation map. A stolen home can identify a presented copy by its credential SAID even if the revocation map is sealed elsewhere. The generator therefore keeps a named credential record when only sealed_revocation_map is on; identity_oracle removes it by giving the home only its agency cryptonym. Rejected treating the sealed map as if it also deleted the home's credential copies, since that would credit an unbuilt countermeasure with protection it has not promised. Tradeoff: sealing alone scores poorly until the home also stops retaining identifying credentials.
    The suite is done when it tells the truth, whatever the stack scores = decision:
      nid: 0v9gy7xe
      why: >-
        The deliverable is a correct measurement: every failing claim named with its cause and an owner. Fixes belong to the components the report names (the issuer, an orchestrator, batch commitment, and spec questions for the spec's editors), and a later run shows what each fix bought. Rejected reading "demonstrate the intended properties" as "make them hold", which would turn the measurement into an unbounded rewrite of the stack it measures. Tradeoff: the first report will be unflattering, by design.
      children:
        A claim names no protection when a required compartment is absent = decision:
          nid: 7sds7vf4
          why: >-
            A scenario can hand a party an Observer, revocation-authority or orchestrator compartment that a real stack does not run. Scoring the other compartments and returning pass would imply protection against the absent component's attack, though that attack was never possible on this stack. Such a claim is not measured; the report still shows the scores from compartments that were present. Rejected counting an absent compartment as an empty observed store, which made combined parties pass falsely. Tradeoff: a cross-stack scenario has more not-measured verdicts, while the attack table still says exactly what linked.
        Commit scored summaries and hashes; keep raw run exports outside Git = decision:
          nid: 9jmmwx2c
          why: >-
            A run's raw exports are thousands of files and hundreds of megabytes, which would make repository history costly to carry and to undo. Commit each run's results.json and rendered reports, the sweep summaries, and a SHA-256 manifest of omitted raw files. Preserve the complete run directories outside Git so a disputed number can still be recomputed; the manifest binds a report to its exact evidence, and a generator run can be reproduced from its scenario. Rejected placing the raw exports or their archive on main. Tradeoff: a reader can recompute a generator join by rerunning its scenario, but cannot recompute a live-stack join from the repository alone.
        Attribute failed claims to the measured adapter = decision:
          nid: 343qkxce
          why: >-
            A cause and owner in a failed-claim report must describe the stack that produced the evidence. A static catalogue owner map that names one stack's components sends a reader of another stack's report to the wrong component even when the attack and score are correct. Keep catalogue ownership, named by role, as a fallback for synthetic design sweeps, and let each live adapter supply owners for the attacks it can produce. Rejected rewriting only one report artifact, because rerunning it would reproduce the false attribution.
