# Writing an adapter

An adapter connects one KERI/ACDC stack to the suite. It drives issuance and presentation as a scenario describes, then hands over every compartment's contents and, separately, the ground truth the scorer needs (`this.i` 364eng34, 9wxr29dq). Attacks never see the stack, only what the adapter exported, so the same attacks run on any stack. The synthetic generator, `src/keri_priv_analysis/generator.py`, is itself an adapter and is the reference for every shape below.

## The interface

An adapter is an object with:

- `name`: the string a scenario's `run.adapter` names.
- `run(scenario, population)`: returns `(compartments, truth, knowledge)`, a `CompartmentSet`, a `GroundTruth` and a `Knowledge` from `keri_priv_analysis.model`. `scenario` is a loaded `Scenario`; `population` is the generated `Population`, whose rows the scenario's citizens are drawn from.
- `provenance()`: a dict naming what was measured, at minimum each component's repository and commit and the hash of the adapter's pin manifest.
- `causes(scenario)`: for each attack name, where in the stack its leak comes from, as file and line when the adapter can say. The report prints it beside every failing claim.

An adapter that cannot honour a stack setting the scenario asks for, such as random registry allocation on a stack that allocates first-in first-out, refuses with `errors.ADAPTER_SETTING` (`e.feature.unsupported.stack-setting.f`). It never quietly runs something else. A countermeasure no stack implements is scored on the generator.

An adapter is its own uv project under `adapters/<name>/`, with its own `pyproject.toml` and `uv.lock`, because each stack pins its own keripy and its own dependencies. It depends on this suite by path and registers itself as an entry point:

```toml
[project.entry-points."keri_priv_analysis.adapters"]
keria = "kpa_adapter_keria:Adapter"
```

Then `uv run kpa run <scenario> --out <dir>` inside the adapter's project runs the scenario on its stack, and `uv run kpa check <scenario>` runs only the contract suite.

## Pins

Each adapter commits `adapters/<name>/manifest.toml`, listing every component of the stack it drives with its repository and full commit SHA, and pins the same commits in its `uv.lock`. `provenance()` reports the manifest's SHA-256. Changing a pin is a commit. The scheduled job installs with `uv sync --locked`, so a stale lock file fails rather than measuring something else.

## Compartments

The adapter returns one `Compartment` for every name in `scenario.compartment_names()`, and the contract suite refuses an adapter that leaves any out. Each has a status:

- `present`: the stack has it and the adapter exported it.
- `absent`: the stack has no such store. Say why in `note`.
- `not-measured`: the store exists but the adapter cannot export it. Say why in `note`. It is never reported as empty.

A present compartment holds four kinds of content and nothing else.

- `streams`: named byte strings in the CESR text domain. `kel:<prefix>` is a KEL replay as the stack publishes it, attachments included; `tel:<registry>` is a registry's TEL events, and for KERI v1 the credentials' own TEL events after the registry's `vcp`; `batch:<n>` is a published Registrar batch as JSON, `{"root": ..., "registries": [...]}`, in published order. KELs and TELs of either generation are read. The public record (`public`) holds the issuers' KELs, every TEL and the batches. A verifier's compartment holds, as `kel:<holder>`, each holder KEL it resolved to verify a presentation.
- `records`: named tables, each a list of rows mapping field names to strings. Attacks look for these fields: in an issuing home's tables, `registry`, `said`, `holder`, `management` (the citizen's management AID, or whatever key the home stores against the citizen) and `time` (seconds, as a string); in identity proofing, `record` and `management`, beside the legal identity's attributes; in the revocation authority, `said` and `management`. Keep every other field the store has, under its own name.
- `logs`: `LogLine(time, source, text)`, one per line the component wrote, with `text` the raw line. A verifier that polls the Registrar's feed itself, as the scenario's `verifier_probing` asks, logs each registry it first sees as `first-seen <registry>`; the verifier-probing attack reads only those lines. `source` is the address the request came from, or the component's own address for its application log.
- `presentations`: one `Presentation` per disclosure the verifier received: an opaque random `handle`, the `verifier`, the `time`, the event `domain`, the `disclosed` attributes, the credential's `said`, `registry`, `issuer` and `holder`, and the presented bytes in `raw`.

Times are seconds from the scenario's start. A real stack cannot wait out a scenario's thirty days, so a real adapter performs the scenario's actions in the scenario's order and records each at its scenario time, keeping the stack's own wall-clock stamps in the bytes and lines it exports. Its report says so.

## Ground truth and knowledge

`GroundTruth` says which simulated citizen each presentation handle, identity record and identifier belongs to: `citizen_rows` (each citizen's population row), `presentations`, `identities`, `artifacts` (every SAID, registry, holder AID and management key issued to one citizen) and `domains`. Identifiers minted for no citizen, such as decoys, are listed in `decoys`. It is written to its own file and never reaches an attack.

`Knowledge` is what any adversary is assumed to know: the copy count per citizen; `per_citizen`, how many credentials (and so registries and issuance events) one citizen's session creates, which attacks size their groups by (an issuer that issues two credentials per copy and a retained pair has a `per_citizen` that is not the copy count); how many issuance anchors that session writes to an issuer's KEL; which issuer AID is which home; the addresses of verifiers and of the State's own services; and `infrastructure`, the public identifiers that belong to no citizen, such as witness AIDs, schema SAIDs and the State's own parties. Attacks never join through an infrastructure identifier, so an adapter that leaves one out makes every citizen look linked through it.

## The contract

`keri_priv_analysis.contract.check(scenario, compartments, truth, knowledge, population)` returns the problems, and the runner refuses to score an adapter with any (Part B item 5):

- every compartment the scenario names is accounted for, and none it does not name is added;
- each citizen made exactly the scenario's number of presentations to each verifier in each domain, each inside its plan's window and disclosing exactly its plan's attributes with the citizen's own values from the population, and every exported presentation is in the ground truth;
- every identifier in a record, a log line or a presentation is one the adapter issued;
- every KEL replays in keripy, the issuers' and the holder KELs verifiers resolved alike; every TEL event chains to its prior and is sealed in its own issuer's KEL; and every presentation's bytes carry the credential it names.

An adapter's own tests run this check on a small scenario, and the scheduled job runs it weekly against the pinned stack.
