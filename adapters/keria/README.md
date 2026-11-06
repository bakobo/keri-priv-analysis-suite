# The KERIA adapter

This adapter runs a scenario on [KERIA](https://github.com/WebOfTrust/keria) agents driven by [SignifyPy](https://github.com/WebOfTrust/signifypy), and hands the suite what each host stored (`docs/adapters.md`, `this.i` 97h32zrn). KERIA's ordinary usage, many credentials in one registry, makes it the natural positive control for the shared-registry attack.

## From a fresh clone to passing tests

The machine needs uv, Python 3.14 and the system libsodium (`libsodium23` on Debian and Ubuntu).

```
cd adapters/keria/stack && uv sync --locked
cd .. && uv sync --locked
uv run pytest
```

`uv run pytest` runs the adapter's tests at 100% branch coverage, the contract suite on `scenarios/contract.toml` against live KERIA agencies, and the stack project's own tests, which hold the driver to 100% branch coverage in its environment. The live tests take about five minutes on an idle machine. `uv run kpa check scenarios/contract.toml` runs only the contract suite; `uv run kpa run scenarios/smoke.toml --out <dir>` runs the smoke scenario (200 citizens, 2 copies), which takes about two hours.

## Two environments

KERIA and SignifyPy need keripy 1.2, and the suite needs keripy 2; both are the package `keri`, so one environment cannot hold both. The adapter is therefore two uv projects:

- `adapters/keria` is the suite's environment. It holds the `Adapter` the suite loads by entry point, turns the scenario into a plan, and builds compartments from what the stack exported.
- `adapters/keria/stack` is KERIA's environment: KERIA 0.4.1, SignifyPy 0.4.2 and keripy 1.2.14, pinned by commit in `manifest.toml` and `stack/uv.lock`. Its driver starts the KERIA agencies, performs the plan through SignifyPy, stops every agency, then opens each host's LMDB stores read only and writes them out as JSON.

The adapter runs the driver as a child process (`uv run --project stack python -m kpa_keria_stack`), with each host's stores under a fresh directory in the system's temporary directory, or under `$KPA_KERIA_WORK` when that is set, and removes it when the run ends. This was cheaper than the alternative, running the whole adapter in KERIA's environment and having the suite read files, because the suite already loads adapters in its own process. Attacks still read only the compartments built from the export, never the stack.

## What it runs

- Each issuing home is its own KERIA agency hosting one issuer agent, whose witnessless AID incepts one registry and issues every credential into it.
- The citizens' hosted agents share one wallet agency, one agent per citizen. Each copy a citizen holds is issued to a fresh AID in that citizen's agent, which SignifyPy makes natural (one `identifiers().create` per copy). One AID per citizen would also be ordinary KERIA usage, but the suite's scenario model gives each presentation a fresh copy and has no attack that joins on a shared holder AID, so per-copy AIDs keep the measurement honest about what the remaining vectors leak.
- Each verifier is its own agency with one agent.
- Issuance is SignifyPy's ordinary flow: the issuer resolves the holder AID's agent OOBI, issues, sends an IPEX grant, and the holder admits. A presentation is the holder's IPEX grant to the verifier, which admits it.
- The credential carries every attribute any of the scenario's presentations discloses. An IPEX grant presents the whole credential and KERIA has no selective disclosure in this flow, so the adapter refuses a scenario in which any presentation's `disclose` list names fewer than all of them.

The scenario asks for bulk copies (`citizens.copies`, one fresh copy per presentation). That is not KERIA's ordinary usage, which presents one credential repeatedly; the adapter issues `copies` credentials per citizen into the one registry because the scenario asks for them.

A real stack cannot wait out a scenario's month, so the driver performs every issuance and presentation in the scenario's order, one after another, and records when each started. The adapter places each action, and every log line and record stamped while it ran, at that action's scenario time. The stack's own wall-clock stamps stay in the bytes and lines: credential and TEL `dt` values, KEL first-seen times and log stamps all describe the minutes the run took, not the scenario's month.

## What it measures

| Compartment | Status | Contents |
|---|---|---|
| `public` | present | Each issuer's KEL as keripy replays it, first-seen attachments included, and each registry's TEL: the `vcp`, then each credential's `iss` in issuance order. KERI v1 throughout. |
| `verifier:<id>` | present | Each presentation: the grant `exn` as the verifier stored it (signatures and pathed attachments), followed by the credential as the verifier stored it on admit. The KEL of each holder AID it resolved, its stored credentials, exchange messages and end-role records, and its agency's log. |
| `issuing-home:<n>` | present | The issuer agent's stores: every credential it issued (SAID, registry, holder AID, schema, `dt`, attribute values), its exchange messages, its end-role records, and its agency's log. |
| `access-log:hosted-agent` | present | The wallet agency's log, and its agents' rows: which agent and controller hold each holder AID, and the credentials they hold. |

The identifiers that belong to no citizen (the issuers', verifiers' and agencies' AIDs, controllers and events, the registries and the schema) go to `Knowledge.infrastructure`, and `Knowledge.per_citizen` is the copy count, since one citizen's session issues one credential per copy.

KERIA has no management AID. A credential row's `management` field is the holder AID's agent AID, read from the end-role record the holder's OOBI left in the issuer's store; one agent serves all of a citizen's AIDs, so it is what the home can key a citizen by.

Every log is what KERIA writes at INFO with request logging on (`--logrequests`). KERIA's request log names the path but not the address a request came from, so each line's source is the host's own address.

## What it reports absent

- `orchestrator`: KERIA has none; the issuer's Signify client drives issuance itself.
- `operation-log`: KERIA keeps each agent's long-running operations in that host's own stores, so they belong to the host's compartment rather than to a separate log. The adapter does not export them.
- `revocation-authority`: the issuer's own agent holds every credential it issued.
- `identity-proofing`: KERIA has none, so no store joins a legal identity to an identifier.
- `access-log:witness` and `access-log:holder-witness`: every AID is witnessless, so no witness runs.
- `access-log:registrar`, `access-log:observer`, `access-log:watcher`: KERIA has no Registrar or Observer, and no watcher runs.
- `access-log:mailbox`: KERIA agents are their own mailboxes; what a holder receives arrives at its hosted agent, whose log is `access-log:hosted-agent`.

## Settings it refuses

The adapter honours a setting only when KERIA's ordinary usage, or a choice its Signify client offers, produces it; `src/kpa_adapter_keria/settings.py` gives the reason for each refusal. It honours both issuance orders and any `dt_granularity`, which SignifyPy applies by truncating the issuance timestamp it sends. It refuses a presentation that discloses less than the whole credential, any registry scope but `issuer`, random allocation, blinded `bup`, status updates, Registrar batches and publication windows, mixed holder networks, holder status reads, hosted agents other than one per citizen, verifier probing, an identity oracle, a sealed revocation map, decoys, planted log material, holder AIDs other than transferable, per-citizen witness sets, cloned or edged copy templates, constant first-seen times, and any anchor order but per-issuance.

## Determinism

One seed fixes the plan, the citizens' rows, every controller AID, every issuer, verifier and holder AID (each AID's key salt comes from the seed) and every registry. It does not fix the bytes: each credential and TEL event carries the wall-clock issuance time, so credential SAIDs differ run to run, and KERIA incepts each agent from a fresh random salt, so agent AIDs differ too.
