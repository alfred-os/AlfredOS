"""Tests for ``alfred.hooks.errors`` — the hook exception taxonomy.

Pins the load-bearing invariants of the three hook error classes:

* Subclass relationships rooted at :class:`alfred.errors.AlfredError`. The
  CLI top-level dispatch and the orchestrator's PR-B ``except`` arms catch
  ``AlfredError`` uniformly; hook errors MUST flow through that catch.
* :class:`alfred.hooks.errors.HookRefusal` is keyword-only and stores its
  four audit-attribution fields verbatim. Operator-facing message is built
  via :func:`alfred.i18n.t` (i18n rule #1 — every operator-facing string
  goes through ``t()``).
* :class:`alfred.hooks.errors.HookSubscriberError` preserves ``__cause__``
  when raised ``from`` an upstream exception — Task-10's call-site relies
  on chained tracebacks for the audit row's "see the audit log" pointer.
* The three i18n catalog keys ``hooks.refusal``,
  ``hooks.subscriber_error`` and ``hooks.subscriber_must_be_async`` resolve
  through :func:`alfred.i18n.t` to a *rendered* string — not the bare key
  fallback the translator falls back to for missing entries
  (no-silent-failure rule #7).
"""

from __future__ import annotations

import pytest

from alfred.errors import AlfredError
from alfred.hooks.errors import HookError, HookRefusal, HookSubscriberError
from alfred.i18n import set_language, t


@pytest.fixture(autouse=True)
def _reset_language() -> None:
    """Pin the language to en-US before each test.

    The translator caches per-language ``gettext.NullTranslations`` instances
    in a module-level dict; resetting via the public ``set_language`` API
    (not by reaching into ``_active_lang`` directly) keeps the tests honest
    about the public surface.
    """
    set_language("en-US")


# ──────────────────────────────────────────────────────────────────────
# 1. Subclass relationships
# ──────────────────────────────────────────────────────────────────────


def test_hook_error_subclasses_alfred_error() -> None:
    """``HookError`` is the hook-subsystem root, hung off ``AlfredError``."""
    assert issubclass(HookError, AlfredError)


def test_hook_refusal_subclasses_hook_error() -> None:
    """``HookRefusal`` is a ``HookError`` so a generic ``except HookError``
    in the dispatcher catches both refusal-and subscriber-error arms.
    """
    assert issubclass(HookRefusal, HookError)
    assert issubclass(HookRefusal, AlfredError)


def test_hook_subscriber_error_subclasses_hook_error() -> None:
    """``HookSubscriberError`` is a ``HookError`` and therefore an
    ``AlfredError`` — picked up by the orchestrator's uniform catch arm.
    """
    assert issubclass(HookSubscriberError, HookError)
    assert issubclass(HookSubscriberError, AlfredError)


# ──────────────────────────────────────────────────────────────────────
# 2. HookRefusal — keyword-only, stores all four fields
# ──────────────────────────────────────────────────────────────────────


def test_hook_refusal_rejects_positional_args() -> None:
    """``HookRefusal.__init__`` is keyword-only — positional calls raise
    ``TypeError``. Verbatim spec §3.1 signature pin.
    """
    with pytest.raises(TypeError):
        HookRefusal(  # type: ignore[misc]
            "memory.episodic.record.pre",
            "memory.episodic.record",
            "dlp policy blocked the payload",
            "corr-1",
        )


def test_hook_refusal_stores_four_attributes() -> None:
    """All four audit-attribution fields are accessible on the instance —
    the dispatcher in Task-10 reads these to build the audit row.
    """
    refusal = HookRefusal(
        hook_id="memory.episodic.record.pre",
        action_id="memory.episodic.record",
        reason="dlp policy blocked the payload",
        correlation_id="corr-xyz",
    )

    assert refusal.hook_id == "memory.episodic.record.pre"
    assert refusal.action_id == "memory.episodic.record"
    assert refusal.reason == "dlp policy blocked the payload"
    assert refusal.correlation_id == "corr-xyz"


def test_hook_refusal_str_substitutes_template_placeholders() -> None:
    """``str(refusal)`` resolves through ``t("hooks.refusal", ...)`` — the
    rendered string contains the *substituted* values, NOT the literal
    ``{hook_id}``/``{action_id}``/``{reason}`` placeholders. This is the
    template-substitution assertion the task spec asks for: prove the
    message was rendered, not that it equals exact English text.
    """
    refusal = HookRefusal(
        hook_id="memory.episodic.record.pre",
        action_id="memory.episodic.record",
        reason="dlp policy blocked the payload",
        correlation_id="corr-xyz",
    )

    rendered = str(refusal)

    # Substituted values appear in the message.
    assert "memory.episodic.record.pre" in rendered
    assert "memory.episodic.record" in rendered
    assert "dlp policy blocked the payload" in rendered
    # And the placeholders themselves DO NOT appear — the format call
    # actually ran.
    assert "{hook_id}" not in rendered
    assert "{action_id}" not in rendered
    assert "{reason}" not in rendered


def test_hook_refusal_str_resolves_through_t_under_language_toggle() -> None:
    """Switching the active language MUST go through the translator path —
    we assert the message resolves via ``t()`` regardless of language.
    With only an en catalog shipping today, both en-US and fr-FR
    (unknown — falls back to en) produce a substituted, non-bare-key
    string. The point is to prove the resolver is wired up, not to pin
    English text.
    """
    refusal = HookRefusal(
        hook_id="hp",
        action_id="ax",
        reason="r",
        correlation_id="c",
    )

    set_language("en-US")
    en_rendered = str(refusal)

    set_language("fr-FR")  # No fr-FR catalog — falls back to en, still rendered.
    fr_rendered = str(refusal)

    # Both are non-empty rendered strings, never the bare msgid key.
    assert en_rendered != "hooks.refusal"
    assert fr_rendered != "hooks.refusal"
    # Both contain the substituted hook_id — proves the format step ran in
    # each language.
    assert "hp" in en_rendered
    assert "hp" in fr_rendered


def test_hook_refusal_does_not_leak_correlation_id_into_message() -> None:
    """The catalog template for ``hooks.refusal`` intentionally does NOT
    embed ``correlation_id`` in the user-visible message — it lives on the
    attribute for the audit row. This test pins that no-leak so a future
    catalog edit cannot silently log the correlation id into operator
    output. (Security rule #1: never log secrets — correlation ids are not
    secrets but the principle of minimal disclosure applies.)
    """
    refusal = HookRefusal(
        hook_id="hp",
        action_id="ax",
        reason="r",
        correlation_id="corr-only-on-attribute",
    )
    assert "corr-only-on-attribute" not in str(refusal)
    # The attribute is still there for the audit row.
    assert refusal.correlation_id == "corr-only-on-attribute"


# ──────────────────────────────────────────────────────────────────────
# 3. HookSubscriberError — chains via `raise ... from exc`
# ──────────────────────────────────────────────────────────────────────


def test_hook_subscriber_error_preserves_cause_when_raised_from() -> None:
    """Raising ``HookSubscriberError(...) from exc`` sets ``__cause__`` to
    the upstream exception — Task-10 relies on this for the audit row's
    chained traceback.
    """
    original = ValueError("subscriber blew up")
    try:
        raise HookSubscriberError(
            t(
                "hooks.subscriber_error",
                name="dlp_scanner",
                correlation_id="corr-1",
            )
        ) from original
    except HookSubscriberError as caught:
        assert caught.__cause__ is original


def test_hook_subscriber_error_str_contains_substituted_name() -> None:
    """When constructed with the rendered ``hooks.subscriber_error``
    message, ``str(error)`` contains the substituted ``name`` /
    ``correlation_id`` — pins the template-substitution wiring for the
    catalog entry.
    """
    message = t("hooks.subscriber_error", name="dlp_scanner", correlation_id="corr-9")
    error = HookSubscriberError(message)
    rendered = str(error)
    assert "dlp_scanner" in rendered
    assert "corr-9" in rendered


# ──────────────────────────────────────────────────────────────────────
# 4. Catalog keys resolve through t() — NOT the bare-key fallback
# ──────────────────────────────────────────────────────────────────────


def test_hooks_refusal_catalog_key_resolves_not_bare() -> None:
    """``hooks.refusal`` is in the catalog. ``t()`` returns the rendered
    template; the bare-key fallback (``raw == key``) returns the key
    itself, which would silently mask a missing catalog entry — the i18n
    rule #4 ``compile --check`` gate plus this test pin both ends.
    """
    rendered = t("hooks.refusal", hook_id="hp", action_id="ax", reason="r")
    assert rendered != "hooks.refusal"
    assert "hp" in rendered


def test_hooks_subscriber_error_catalog_key_resolves_not_bare() -> None:
    """Same shape as ``test_hooks_refusal_catalog_key_resolves_not_bare``
    for ``hooks.subscriber_error``.
    """
    rendered = t("hooks.subscriber_error", name="x", correlation_id="c")
    assert rendered != "hooks.subscriber_error"
    assert "x" in rendered
    assert "c" in rendered


def test_hooks_subscriber_must_be_async_catalog_key_resolves_not_bare() -> None:
    """``hooks.subscriber_must_be_async`` is the decorator-rejection key
    (Task-7's call-site). It lands NOW so the catalog gate stays green
    once Task-7 wires it.
    """
    rendered = t("hooks.subscriber_must_be_async", name="my_sync_subscriber")
    assert rendered != "hooks.subscriber_must_be_async"
    assert "my_sync_subscriber" in rendered
