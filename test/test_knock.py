import pytest
from conftest import DEFAULT_KNOCK_SEQUENCE, DEFAULT_TARGET_PORT, wait_for_trace
from utils.net import (
    port_closed,
    port_filtered,
    send_udp_packet,
    send_udp_packet_from_ip,
)

DST_IP = "127.0.0.1"
WRONG_CODE = 4444


@pytest.mark.usefixtures("loader")
def test_port_filtered_by_default():
    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)
    assert wait_for_trace(f"debug: tcp port: {DEFAULT_TARGET_PORT}")


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
    send_udp_packet_from_ip(DST_IP, DEFAULT_KNOCK_SEQUENCE[0], "127.0.0.5")

    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_wrong_code_udp_packet_sent():
    send_udp_packet(DST_IP, WRONG_CODE)

    assert port_filtered(DST_IP, DEFAULT_TARGET_PORT)
