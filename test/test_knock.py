import time

import pytest
from conftest import (
    DEFAULT_KNOCK_SEQUENCE,
    DEFAULT_TARGET_PORT,
    clear_trace,
    wait_for_trace,
)
from utils.net import (
    port_closed,
    port_closed_from_ip,
    port_filtered,
    send_udp_packet,
    send_udp_packet_from_ip,
)

DST_IP = "127.0.0.1"
ALT_SRC_IP = "127.0.0.5"
WRONG_CODE = 4444


@pytest.mark.parametrize(
    "loader",
    [
        {"target_port": DEFAULT_TARGET_PORT, "knock_sequence": DEFAULT_KNOCK_SEQUENCE},
        {"target_port": 1024, "knock_sequence": DEFAULT_KNOCK_SEQUENCE},
        {"target_port": 65535, "knock_sequence": DEFAULT_KNOCK_SEQUENCE},
    ],
    indirect=True,
)
def test_port_filtered_by_default(loader):
    config, _ = loader

    assert port_filtered(DST_IP, config["target_port"])
    assert wait_for_trace(f"debug: tcp port: {config['target_port']}")


@pytest.mark.usefixtures("loader")
def test_port_closed_when_correct_code_udp_packets_sent():
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[0])
    assert wait_for_trace("info: code 1 passed")
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[1])
    assert wait_for_trace("info: code 2 passed")
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[2])
    assert wait_for_trace("info: code 3 passed")
    assert wait_for_trace("info: sequence complete")

    # should be closed rather than filtered now
    assert port_closed(DST_IP, DEFAULT_TARGET_PORT)


@pytest.mark.parametrize(
    "loader",
    [
        {"target_port": DEFAULT_TARGET_PORT, "knock_sequence": [123, 456, 789]},
        {"target_port": DEFAULT_TARGET_PORT, "knock_sequence": [123, 456]},
        {"target_port": DEFAULT_TARGET_PORT, "knock_sequence": [123]},
    ],
    indirect=True,
)
def test_port_closed_when_correct_codes_sent(loader):
    config, _ = loader
    for i, code in enumerate(config["knock_sequence"]):
        send_udp_packet(DST_IP, code)
        assert wait_for_trace(f"info: code {i + 1} passed")

    assert wait_for_trace("info: sequence complete")
    assert port_closed(DST_IP, DEFAULT_TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_wrong_code_sent_in_middle_of_correct_codes():
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[0])
    assert wait_for_trace("info: code 1 passed")
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[1])
    assert wait_for_trace("info: code 2 passed")
    send_udp_packet(DST_IP, WRONG_CODE)
    assert wait_for_trace("info: sequence reset")
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[2])

    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_only_one_code_udp_packet_sent():
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[0])

    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_correct_code_udp_packet_sent_from_wrong_ip():
    send_udp_packet_from_ip(DST_IP, DEFAULT_KNOCK_SEQUENCE[0], ALT_SRC_IP)

    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_ports_closed_when_correct_codes_sent_from_multiple_ips():
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[0])
    assert wait_for_trace("info: code 1 passed")
    send_udp_packet_from_ip(DST_IP, DEFAULT_KNOCK_SEQUENCE[0], ALT_SRC_IP)
    assert wait_for_trace("info: code 1 passed")

    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[1])
    assert wait_for_trace("info: code 2 passed")
    send_udp_packet_from_ip(DST_IP, DEFAULT_KNOCK_SEQUENCE[1], ALT_SRC_IP)
    assert wait_for_trace("info: code 2 passed")

    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[2])
    assert wait_for_trace("info: code 3 passed")
    assert wait_for_trace("info: sequence complete")
    send_udp_packet_from_ip(DST_IP, DEFAULT_KNOCK_SEQUENCE[2], ALT_SRC_IP)
    assert wait_for_trace("info: code 3 passed")
    assert wait_for_trace("info: sequence complete")

    assert port_closed(DST_IP, DEFAULT_TARGET_PORT)
    assert port_closed_from_ip(DST_IP, DEFAULT_TARGET_PORT, ALT_SRC_IP)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_wrong_code_udp_packet_sent():
    send_udp_packet(DST_IP, WRONG_CODE)

    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)


@pytest.mark.parametrize(
    "loader",
    [{"extra_args": ["-t", "500"]}, {"extra_args": ["--timeout", "500"]}],
    indirect=True,
)
def test_port_filtered_when_wrong_code_udp_packet_sent_with_timeout(loader):
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[0])
    assert wait_for_trace("info: code 1 passed")
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[1])
    assert wait_for_trace("info: code 2 passed")
    time.sleep(1)
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[2])
    assert wait_for_trace("info: sequence timeout")

    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)


@pytest.mark.parametrize("loader", [{"extra_args": ["-t", "500"]}], indirect=True)
def test_sequence_timeout_resets_sequence(loader):
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[0])
    assert wait_for_trace("info: code 1 passed")
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[1])
    assert wait_for_trace("info: code 2 passed")
    time.sleep(1)
    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[2])
    assert wait_for_trace("info: sequence timeout")
    clear_trace()

    send_udp_packet(DST_IP, DEFAULT_KNOCK_SEQUENCE[0])
    assert wait_for_trace("info: code 1 passed")


@pytest.mark.parametrize(
    "loader",
    [
        {"knock_sequence": [111], "extra_args": ["-s", "500"]},
        {"knock_sequence": [111], "extra_args": ["--session-timeout", "500"]},
    ],
    indirect=True,
)
def test_port_filtered_when_session_timeout_reached(loader):
    config, _ = loader
    send_udp_packet(DST_IP, config["knock_sequence"][0])
    assert wait_for_trace("info: code 1 passed")
    assert wait_for_trace("info: sequence complete")

    assert port_closed(DST_IP, DEFAULT_TARGET_PORT)
    time.sleep(1)
    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)
    assert wait_for_trace("info: session timed out")


@pytest.mark.parametrize(
    "loader", [{"knock_sequence": [111], "extra_args": ["-s", "500"]}], indirect=True
)
def test_port_filtered_and_sequence_reset_when_session_timeout_reached(loader):
    config, _ = loader
    send_udp_packet(DST_IP, config["knock_sequence"][0])
    assert port_closed(DST_IP, DEFAULT_TARGET_PORT)
    time.sleep(1)
    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)
    assert wait_for_trace("info: session timed out")
    clear_trace()

    send_udp_packet(DST_IP, config["knock_sequence"][0])
    assert wait_for_trace("info: code 1 passed")
