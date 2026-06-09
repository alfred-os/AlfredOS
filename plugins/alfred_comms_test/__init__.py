"""Alfred comms-test reference plugin.

Full-lifecycle comms adapter (PR-S4-8, #152) exercising the ADR-0024
eight-method wire contract host-side: it answers ``lifecycle.start`` /
``lifecycle.stop`` / ``adapter.health`` / ``outbound.message`` and emits the four
plugin -> host notifications (``inbound.message``, ``adapter.binding_request``,
``adapter.rate_limit_signal``, ``adapter.crashed``) on internal test triggers.
The fabricated-inbound injector is gated on ``ALFRED_ENV=test`` (see
``main.inject_inbound``). Upgraded from the Slice-3 one-shot echo stub.

The on-disk directory uses an underscore (``alfred_comms_test``) so the
package is importable by mypy / pyright — a hyphenated dir containing
``__init__.py`` confuses the type-checker (mypy: "alfred-comms-test
contains __init__.py but is not a valid Python package name"). The
underscore form follows the established ``alfred_quarantined_llm`` /
``alfred_web_fetch`` precedent from PR-S3-3a / PR-S3-5. The manifest's
publicly-visible ``id = "alfred.comms-test"`` keeps the hyphen; the
supervisor resolves the on-disk path via ``Path``, never by ``import``.
"""
