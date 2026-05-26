"""Per-coroutine isolation of the active language (spec §0.1).

Pre-refactor: ``_active_lang`` is a module-global, so the second coroutine's
``set_language()`` clobbers the first under interleaving — Bob's English bleeds
into Alice's German between the ``await`` points. Post-refactor (ContextVar)
asyncio propagates the per-coroutine value across ``await`` automatically,
so each handler sees its own language without any handler-side bookkeeping.

The shape we assert is ``before == after`` per coroutine: every ``t()`` call
inside coroutine A must resolve against A's set language, regardless of what
coroutine B has done in the meantime. To make the bug observable independent
of the on-disk catalog (today the repo ships only an ``en`` catalog, so a
naive ``t()`` call resolves identically for any BCP-47 tag), we monkeypatch
``_load`` with a fake that maps each language to a distinct ``gettext`` output.
That keeps the test deterministic, catalog-independent, and locked to the
refactor itself rather than to any specific catalog entry.
"""

from __future__ import annotations

import asyncio
import gettext

import pytest

from alfred.i18n import translator as translator_module
from alfred.i18n.translator import set_language, t


class _MarkerTranslator(gettext.NullTranslations):
    """Stub translator that tags every lookup with the active language.

    Pairing this with a monkeypatched ``_load`` makes the per-coroutine
    language observable in ``t()``'s return value without touching the
    on-disk catalog. ``gettext()`` returns ``"<lang>:<key>"`` so the test
    can assert that each coroutine's ``t()`` calls were resolved against
    the language it set, not whichever language ran the most recent
    ``set_language()`` on the module global.
    """

    def __init__(self, lang: str) -> None:
        super().__init__()
        self._lang = lang

    def gettext(self, message: str) -> str:  # type: ignore[override]
        return f"{self._lang}:{message}"


@pytest.mark.asyncio
async def test_set_language_isolates_per_coroutine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two interleaved coroutines must each see their own language.

    Property: at every ``await`` point inside coroutine A, ``t()`` resolves
    against A's set language, regardless of what coroutine B has done in the
    meantime. Pre-refactor this test fails because the second ``set_language``
    call clobbers the global; post-refactor it passes because each coroutine
    runs in its own ContextVar context.
    """

    monkeypatch.setattr(translator_module, "_load", _MarkerTranslator)
    # The cache would otherwise short-circuit our fake loader on the second call.
    monkeypatch.setattr(translator_module, "_translators", {})

    async def alice() -> tuple[str, str]:
        set_language("de-DE")
        before = t("cli.help.root")
        await asyncio.sleep(0)  # yield — bob runs and would clobber the global.
        after = t("cli.help.root")
        return before, after

    async def bob() -> tuple[str, str]:
        set_language("en-US")
        before = t("cli.help.root")
        await asyncio.sleep(0)
        after = t("cli.help.root")
        return before, after

    alice_result, bob_result = await asyncio.gather(alice(), bob())
    # Shape assertion: each coroutine's pre- and post-yield t() resolve identically.
    # Pre-refactor this fails because bob's set_language("en-US") leaks into alice's
    # post-yield call — alice would see ``en-US:cli.help.root`` after the yield
    # instead of ``de-DE:cli.help.root``.
    assert alice_result[0] == alice_result[1], (
        f"alice's language leaked across await: {alice_result!r}"
    )
    assert bob_result[0] == bob_result[1], f"bob's language leaked across await: {bob_result!r}"
    # And cross-check that the two coroutines genuinely saw different languages —
    # otherwise an implementation that always returned the same value would pass
    # the per-coroutine assertions vacuously.
    assert alice_result[0] != bob_result[0], (
        f"alice and bob saw the same language; fake loader is misconfigured: "
        f"{alice_result!r} vs {bob_result!r}"
    )
