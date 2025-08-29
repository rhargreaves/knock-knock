import pytest
from conftest import DEFAULT_TARGET_PORT


@pytest.mark.parametrize(
    "loader",
    [{"target_port": DEFAULT_TARGET_PORT, "knock_sequence": [123] * 11}],
    indirect=True,
)
def test_rejects_sequence_longer_than_max_length(loader):
    _, proc = loader

    assert "Error: sequence length cannot exceed 10" in proc.stderr.read()


@pytest.mark.parametrize(
    "loader",
    [{"target_port": DEFAULT_TARGET_PORT, "knock_sequence": []}],
    indirect=True,
)
def test_rejects_empty_sequence(loader):
    _, proc = loader

    assert "sequence is required" in proc.stderr.read()
