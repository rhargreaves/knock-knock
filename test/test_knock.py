import pytest
from conftest import wait_for_trace
from utils.net import (
    port_closed,
    port_filtered,
    send_udp_packet,
    send_udp_packet_from_ip,
)

TARGET_PORT = 6666
DST_IP = "127.0.0.1"


@pytest.mark.usefixtures("loader")
def test_port_filtered_by_default():
    assert port_filtered(DST_IP, TARGET_PORT)
    assert wait_for_trace("debug: tcp port: 6666")


@pytest.mark.usefixtures("loader")
def test_port_closed_when_correct_code_udp_packets_sent():
    CODE_1 = 1111
    CODE_2 = 2222
    CODE_3 = 3333

    send_udp_packet(DST_IP, CODE_1)
    assert wait_for_trace("info: code 1 passed")
    send_udp_packet(DST_IP, CODE_2)
    assert wait_for_trace("info: code 2 passed")
    send_udp_packet(DST_IP, CODE_3)
    assert wait_for_trace("info: code 3 passed")
    assert wait_for_trace("info: sequence complete")

    # should be closed rather than filtered now
    assert port_closed(DST_IP, TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_wrong_code_sent_in_middle_of_correct_codes():
    CODE_1 = 1111
    CODE_2 = 2222
    CODE_WRONG = 4444
    CODE_3 = 3333

    send_udp_packet(DST_IP, CODE_1)
    assert wait_for_trace("info: code 1 passed")
    send_udp_packet(DST_IP, CODE_2)
    assert wait_for_trace("info: code 2 passed")
    send_udp_packet(DST_IP, CODE_WRONG)
    assert wait_for_trace("info: sequence reset")
    send_udp_packet(DST_IP, CODE_3)

    assert port_filtered(DST_IP, TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_only_one_code_udp_packet_sent():
    CODE_1 = 1111

    send_udp_packet(DST_IP, CODE_1)

    assert port_filtered(DST_IP, TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_correct_code_udp_packet_sent_from_wrong_ip():
    CODE_1 = 1111

    send_udp_packet_from_ip(DST_IP, CODE_1, "127.0.0.5")

    assert port_filtered(DST_IP, TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_wrong_code_udp_packet_sent():
    WRONG_CODE_1 = 1221

    send_udp_packet(DST_IP, WRONG_CODE_1)

    assert port_filtered(DST_IP, TARGET_PORT)
