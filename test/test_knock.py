import socket
import subprocess

import pytest
from conftest import wait_for_trace

TARGET_PORT = 6666


def port_filtered(dst_ip, port):
    cmd = ["nc", "-zvw", "2", dst_ip, str(port)]
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"Command output:\n{result.stdout}")
    if result.stderr:
        print(f"Command stderr:\n{result.stderr}")

    if result.returncode == 1:
        if "Connection refused" in result.stderr:
            return False
        elif "timed out" in result.stderr or result.stderr.strip() == "":
            return True
    return False


def port_closed(dst_ip, port):
    cmd = ["nc", "-z", dst_ip, str(port)]
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"Command output:\n{result.stdout}")
    if result.stderr:
        print(f"Command stderr:\n{result.stderr}")
    return result.returncode == 1


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


def port_closed_native(dst, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect((dst, port))
        return False
    except ConnectionRefusedError:
        return True
    finally:
        sock.close()


def port_filtered_native(dst, port):
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
def test_port_closed_when_correct_code_udp_packet_sent():
    dst = "127.0.0.1"

    CODE_1 = 1111

    send_udp_packet(dst, CODE_1)

    # should be closed rather than filtered now
    assert port_closed_native(dst, TARGET_PORT)


@pytest.mark.usefixtures("loader")
def test_port_filteed_when_wrong_code_udp_packet_sent():
    dst = "127.0.0.1"

    WRONG_CODE_1 = 1221

    send_udp_packet(dst, WRONG_CODE_1)

    assert port_filtered_native(dst, TARGET_PORT)
