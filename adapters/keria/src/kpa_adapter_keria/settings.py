"""Which stack settings KERIA with Signify honours, and why it refuses the rest.

A setting is honoured only when this stack's ordinary usage, or a choice its Signify client really
offers, produces what the setting describes (docs/adapters.md). Every other value is refused with
errors.ADAPTER_SETTING rather than run as something else.
"""

from __future__ import annotations

from keri_priv_analysis import errors

ADAPTER = "keria"

# setting -> (the values KERIA honours, why the others are refused)
HONOURED: dict[str, tuple[tuple, str]] = {
    "registry_scope": (("issuer",), ("a KERIA issuer issues every credential into the one "
                       "registry it names, which is KERIA's ordinary usage; a registry per "
                       "credential or per citizen is a pool KERIA has no allocator for.")),
    "registry_allocation": (("fifo",), ("with one registry per issuer there is no pool to "
                            "allocate from at random.")),
    "issuance_order": (("per-citizen", "mixed"), ""),
    "tel_updates": (("upd",), ("KERIA's TEL is KERI v1, which issues a public iss event per "
                    "credential, the v1 counterpart of a public upd; it has no blinded update.")),
    "status_updates": (("none",), ("the adapter issues and presents; it does not revoke, so no "
                       "status update follows issuance.")),
    "batch_size": ((0,), "KERIA publishes no Registrar batches."),
    "publication_window": ((0.0,), ("KERIA has no Registrar; each TEL event is available from "
                           "the issuer's agent when it is made.")),
    "holder_network": (("direct",), ("the holder's traffic reaches its hosted agent directly; "
                       "KERIA has no mixing relay.")),
    "holder_status_reads": ((False,), "KERIA has no Observer for a holder to read status from."),
    "hosted_agents": (("per-citizen",), ("KERIA boots one agent per Signify controller, and each "
                      "citizen is one controller; neither no agent nor an agent shared across "
                      "citizens is how KERIA is used.")),
    "verifier_probing": ((False,), "KERIA has no Registrar feed for a verifier to poll."),
    "identity_oracle": ((False,), "KERIA has no identity proofing."),
    "sealed_revocation_map": ((False,), ("the issuer's agent keeps every credential it issued, "
                              "with its holder; KERIA has no separate revocation authority to "
                              "seal a map in.")),
    "decoys": ((0,), "KERIA issues no decoy credentials."),
    "log_join_material": ((False,), "the adapter exports what KERIA logs and plants nothing."),
    "holder_aids": (("transferable",), ("Signify AIDs are transferable; the adapter does not "
                    "delegate holder AIDs, and KERIA hosts no non-transferable ones.")),
    "holder_witnesses": (("pool",), ("holder AIDs are witnessless, which the generator's pool "
                         "setting comes closest to; one witness set per citizen is not run.")),
    "copy_template": (("fresh",), ("each copy is a fresh credential to a fresh holder AID; "
                      "KERIA's issuer does not clone attribute blocks or add shared edges.")),
    "first_seen": (("exact",), ("keripy stamps each KEL event's first-seen time from the wall "
                   "clock (keri/core/eventing.py:3131), and KERIA replays it.")),
    "anchor_order": (("issuance",), ("Signify anchors each issuance in its own interaction event "
                     "as it issues (signify/app/credentialing.py:759).")),
}
# Settings any value of which KERIA honours, or which nothing reads when it is off.
FREE = ("dt_granularity", "retention", "batch_mix")


def check_disclosure(scenario) -> None:
    """Refuse a presentation that discloses less than the whole credential. An IPEX grant presents
    the credential entire, and the credential carries every attribute any presentation discloses,
    so a plan naming fewer would claim a selective disclosure KERIA does not make."""
    carried = set().union(*(p.disclose for p in scenario.presentations))
    for n, plan in enumerate(scenario.presentations):
        if set(plan.disclose) != carried:
            raise errors.ADAPTER_SETTING(
                adapter=ADAPTER, setting=f"presentation[{n}].disclose", value=list(plan.disclose),
                reason="an IPEX grant presents the whole credential, which carries "
                f"{', '.join(sorted(carried))}; every presentation must disclose all of them.")


def check(stack) -> None:
    """Refuse the first setting KERIA does not honour."""
    for setting, (allowed, reason) in HONOURED.items():
        value = getattr(stack, setting)
        if value not in allowed:
            raise errors.ADAPTER_SETTING(adapter=ADAPTER, setting=setting, value=value,
                                         reason=reason)
