import socket

import pytest
from conftest import wait_for_trace

TARGET_PORT = 6666


@pytest.mark.usefixtures("loader")
def test_port_filtered_by_default():
    dst = "127.0.0.1"
    assert port_filtered(dst, TARGET_PORT)
    assert wait_for_trace("Hello tcp port 6666", timeout=5.0)


def send_udp_packet(dst, port):
    print(f"Sending UDP packet to {dst}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b"", (dst, port))
        print(f"Sent UDP packet to {dst}:{port}")
    finally:
        sock.close()


def send_udp_packet_from_ip(dst, port, src_ip):
    print(f"Sending UDP packet from {src_ip} to {dst}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((src_ip, 0))
        sock.sendto(b"", (dst, port))
        print(f"Sent UDP packet from {src_ip} to {dst}:{port}")
    finally:
        sock.close()


def port_closed(dst, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect((dst, port))
        return False
    except ConnectionRefusedError:
        return True
    finally:
        sock.close()


def port_filtered(dst, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect((dst, port))
        return False
    except TimeoutError:
        return True
    except ConnectionRefusedError:
        return False
    finally:
        sock.close()


@pytest.mark.usefixtures("loader")
def test_port_closed_when_correct_code_udp_packets_sent():
    dst = "127.0.0.1"

    CODE_1 = 1111
    CODE_2 = 2222
    CODE_3 = 3333

    send_udp_packet(dst, CODE_1)
    assert wait_for_trace("Code 1 passed.", timeout=5.0)
    send_udp_packet(dst, CODE_2)
    assert wait_for_trace("Code 2 passed.", timeout=5.0)
    send_udp_packet(dst, CODE_3)
    assert wait_for_trace("Code 3 passed. Sequence complete.", timeout=5.0)

    # should be closed rather than filtered now
    assert port_closed(dst, TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_only_one_code_udp_packet_sent():
    dst = "127.0.0.1"

    CODE_1 = 1111

    send_udp_packet(dst, CODE_1)

    assert port_filtered(dst, TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_correct_code_udp_packet_sent_from_wrong_ip():
    dst = "127.0.0.1"

    CODE_1 = 1111

    send_udp_packet_from_ip(dst, CODE_1, "127.0.0.5")

    assert port_filtered(dst, TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filtered_when_wrong_code_udp_packet_sent():
    dst = "127.0.0.1"

    WRONG_CODE_1 = 1221

    send_udp_packet(dst, WRONG_CODE_1)

    assert port_filtered(dst, TARGET_PORT)
