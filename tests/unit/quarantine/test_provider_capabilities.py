"""Tests for ``ProviderCapability`` enum + ``register_provider`` decorator.

PR-S3-4 Task 1 + Task 2 (spec §6.1, §6.2).

Why this lives in ``tests/unit/quarantine/`` rather than ``tests/unit/providers/``:
the capability system exists *because* the quarantined-LLM dispatch path
needs to branch on it (spec §6.2). The provider tests are pre-Slice-3 and
test the slice-1 completion contract; capabilities are a slice-3 addition
load-bearing for the dual-LLM split.

``register_provider`` is a runtime registration decorator that fires for
duck-typed concrete provider classes (which is the real pattern —
``AnthropicProvider`` and ``DeepSeekProvider`` do NOT inherit from the
``Provider`` Protocol). ``__init_subclass__`` on ``typing.Protocol`` does
not fire for duck-typed subclasses, so the decorator is the only place
the registration assertion can land at import time (prov-001 / arch-002).

Task 2 — provider capability constants:
* ``AnthropicProvider.CAPABILITIES`` is a class-level constant frozenset;
  tests must use it directly to avoid the constructor dependency on an
  SDK ``client`` instance (prov-007).
* ``DeepSeekProvider`` is model-aware (prov-009): ``deepseek-chat``
  supports JSON-object mode; ``deepseek-reasoner`` does not. The
  ``_capabilities_for_model`` classmethod is the dispatch point.
"""

from __future__ import annotations

import pytest

from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.base import Provider, ProviderCapability, register_provider
from alfred.providers.deepseek import DeepSeekProvider


# ---------------------------------------------------------------------------
# ProviderCapability enum surface (Task 1)
# ---------------------------------------------------------------------------


def test_provider_capability_has_native_constrained_generation() -> None:
    # The only Slice-3 consumer; Anthropic tool-use shape dispatches here.
    assert ProviderCapability.NATIVE_CONSTRAINED_GENERATION


def test_provider_capability_has_json_object_mode() -> None:
    # DeepSeek classification (spec §6.2 reclassification).
    assert ProviderCapability.JSON_OBJECT_MODE


def test_provider_capability_has_tool_use() -> None:
    # Pre-declared per PRD §6.6 line 290.
    assert ProviderCapability.TOOL_USE


def test_provider_capability_has_vision() -> None:
    assert ProviderCapability.VISION


def test_provider_capability_has_long_context_1m() -> None:
    assert ProviderCapability.LONG_CONTEXT_1M


def test_provider_capability_native_constrained_value_is_stable() -> None:
    # Audit rows persist ``extraction_mode`` strings derived from the
    # capability identity. A drift in the enum's underlying value would
    # silently break audit-row continuity across versions.
    assert ProviderCapability.NATIVE_CONSTRAINED_GENERATION.value == "native_constrained_generation"


def test_provider_capability_json_object_mode_value_is_stable() -> None:
    assert ProviderCapability.JSON_OBJECT_MODE.value == "json_object_mode"


# ---------------------------------------------------------------------------
# Provider Protocol surface (Task 1)
# ---------------------------------------------------------------------------


def test_provider_protocol_declares_capabilities() -> None:
    # capabilities() is a Protocol method on Provider — every concrete
    # provider must implement it. Asserting attribute existence is the
    # right level here: structural Protocol membership is verified by
    # mypy/pyright, not at runtime.
    assert hasattr(Provider, "capabilities")


# ---------------------------------------------------------------------------
# register_provider decorator (Task 1) — prov-001 / arch-002.
# ---------------------------------------------------------------------------


def test_register_provider_rejects_class_missing_capabilities() -> None:
    """register_provider() raises TypeError at import time for a class that
    doesn't declare capabilities() (prov-001 / arch-002).

    This is the failure mode __init_subclass__ on Provider Protocol does NOT
    catch — concrete providers are duck-typed and never inherit from Provider.
    """
    with pytest.raises(TypeError, match="capabilities"):

        @register_provider
        class _BadProvider:
            # No capabilities() method.
            async def complete(self, *args: object, **kwargs: object) -> object:
                return None


def test_register_provider_accepts_class_with_capabilities() -> None:
    @register_provider
    class _GoodProvider:
        async def complete(self, *args: object, **kwargs: object) -> object:
            return None

        def capabilities(self) -> frozenset[ProviderCapability]:
            return frozenset({ProviderCapability.TOOL_USE})

    # Decorator returns the class unchanged (identity).
    assert _GoodProvider.__name__ == "_GoodProvider"
    instance = _GoodProvider()
    assert ProviderCapability.TOOL_USE in instance.capabilities()


def test_register_provider_returns_class_unchanged() -> None:
    """The decorator is identity at the value level — no wrapping, no
    metaclass tricks. The class object that goes in is the class object
    that comes out so static-analysis tooling sees the same symbol the
    source file declared.
    """

    class _Plain:
        def capabilities(self) -> frozenset[ProviderCapability]:
            return frozenset()

    decorated = register_provider(_Plain)
    assert decorated is _Plain


# ---------------------------------------------------------------------------
# AnthropicProvider capabilities (Task 2) — prov-007.
# ---------------------------------------------------------------------------


def test_anthropic_provider_capabilities_constant_includes_native_constrained() -> None:
    """CAPABILITIES is a class-level constant — no constructor required.

    prov-007: existing constructors take ``client`` (an SDK instance), not
    ``api_key``. Tests use the class-level constant to keep capability
    assertions zero-dependency.
    """
    assert ProviderCapability.NATIVE_CONSTRAINED_GENERATION in AnthropicProvider.CAPABILITIES


def test_anthropic_provider_capabilities_constant_is_frozenset() -> None:
    # frozenset so the constant cannot be mutated by a caller.
    assert isinstance(AnthropicProvider.CAPABILITIES, frozenset)


def test_anthropic_provider_capabilities_does_not_include_json_object_mode() -> None:
    # Anthropic's native path is NATIVE_CONSTRAINED_GENERATION (tool-use shape).
    # JSON_OBJECT_MODE is the DeepSeek reclassification; declaring it on
    # Anthropic would route to the wrong dispatch branch.
    assert ProviderCapability.JSON_OBJECT_MODE not in AnthropicProvider.CAPABILITIES


# ---------------------------------------------------------------------------
# DeepSeekProvider model-aware capabilities (Task 2) — prov-009.
# ---------------------------------------------------------------------------


def test_deepseek_chat_supports_json_object_mode() -> None:
    """``deepseek-chat`` supports JSON mode → JSON_OBJECT_MODE capability."""
    caps = DeepSeekProvider._capabilities_for_model("deepseek-chat")
    assert ProviderCapability.JSON_OBJECT_MODE in caps


def test_deepseek_chat_does_not_claim_native_constrained() -> None:
    """``deepseek-chat`` JSON mode is unconstrained — only Anthropic's
    tool-use shape qualifies as NATIVE_CONSTRAINED_GENERATION (spec §6.2).
    """
    caps = DeepSeekProvider._capabilities_for_model("deepseek-chat")
    assert ProviderCapability.NATIVE_CONSTRAINED_GENERATION not in caps


def test_deepseek_reasoner_does_not_support_json_object_mode() -> None:
    """``deepseek-reasoner`` does NOT support JSON mode (prov-009).

    Capability declaration must be model-aware: a single per-class constant
    would mis-classify reasoner and route to the wrong dispatch branch.
    """
    caps = DeepSeekProvider._capabilities_for_model("deepseek-reasoner")
    assert ProviderCapability.JSON_OBJECT_MODE not in caps


def test_deepseek_reasoner_empty_capabilities() -> None:
    """``deepseek-reasoner`` has no Slice-3 capabilities at all."""
    caps = DeepSeekProvider._capabilities_for_model("deepseek-reasoner")
    assert caps == frozenset()


def test_deepseek_unknown_model_returns_default_empty_capabilities() -> None:
    """Unknown model name → empty set (fail-closed dispatch).

    An unknown model in capability-declaration land routes to
    ``prompt_embedded_fallback`` — the most-defensive branch. The same
    fail-closed pattern as the cost-pricing fallback.
    """
    caps = DeepSeekProvider._capabilities_for_model("deepseek-future-model-v9")
    assert caps == frozenset()


# ---------------------------------------------------------------------------
# Instance method capabilities() forwards to the model-aware path (Task 2).
# ---------------------------------------------------------------------------


def test_anthropic_capabilities_instance_method_returns_constant() -> None:
    """The instance ``capabilities()`` method returns ``CAPABILITIES``."""
    # Use ``__new__`` to skip the constructor (which needs a real client).
    provider = AnthropicProvider.__new__(AnthropicProvider)
    assert provider.capabilities() == AnthropicProvider.CAPABILITIES


def test_deepseek_capabilities_instance_method_is_model_aware() -> None:
    """The instance method dispatches on the bound model."""
    chat_provider = DeepSeekProvider.__new__(DeepSeekProvider)
    chat_provider._model = "deepseek-chat"  # type: ignore[attr-defined]
    assert ProviderCapability.JSON_OBJECT_MODE in chat_provider.capabilities()

    reasoner_provider = DeepSeekProvider.__new__(DeepSeekProvider)
    reasoner_provider._model = "deepseek-reasoner"  # type: ignore[attr-defined]
    assert ProviderCapability.JSON_OBJECT_MODE not in reasoner_provider.capabilities()
