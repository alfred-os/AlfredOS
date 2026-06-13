"""Per-boot lifecycle epoch factory (Spec A G1 / ADR-0033) (#237)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from alfred.bootstrap.lifecycle_epoch import (
    BootEpochAlreadyMintedError,
    current_boot_epoch,
    mint_boot_epoch,
    reset_boot_epoch_for_tests,
)


@pytest.fixture(autouse=True)
def _clean_epoch_slot() -> Iterator[None]:
    reset_boot_epoch_for_tests()
    yield
    reset_boot_epoch_for_tests()


def test_mint_returns_non_empty_hex_string() -> None:
    epoch = mint_boot_epoch()
    assert isinstance(epoch, str)
    assert len(epoch) == 32  # uuid4().hex
    int(epoch, 16)  # raises if not hex


def test_mint_registers_current_epoch() -> None:
    assert current_boot_epoch() is None
    epoch = mint_boot_epoch()
    assert current_boot_epoch() == epoch


def test_second_mint_raises() -> None:
    mint_boot_epoch()
    with pytest.raises(BootEpochAlreadyMintedError):
        mint_boot_epoch()


def test_two_processes_get_distinct_epochs() -> None:
    first = mint_boot_epoch()
    reset_boot_epoch_for_tests()
    second = mint_boot_epoch()
    assert first != second
