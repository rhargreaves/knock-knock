import subprocess

import pytest
from conftest import wait_for_trace

TARGET_PORT = 6666


def ping_in_netns(netns, dst_ip):
    cmd = ["ip", "netns", "exec", netns, "ping", "-c1", "-W1", dst_ip]
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    print(f"Command output:\n{result.stdout}")
    if result.stderr:
        print(f"Command stderr:\n{result.stderr}")


def port_closed_in_netns(netns, dst_ip, port):
    cmd = ["ip", "netns", "exec", netns, "nc", "-z", dst_ip, str(port)]
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"Command output:\n{result.stdout}")
    if result.stderr:
        print(f"Command stderr:\n{result.stderr}")
    return result.returncode == 1


@pytest.mark.usefixtures("loader")
def test_icmp_printk(veth_netns):
    dst = veth_netns["host_ip"]
    ping_in_netns(veth_netns["ns"], dst)
    assert wait_for_trace("Hello ping", timeout=5.0)


@pytest.mark.usefixtures("loader")
def test_port_blocked_by_default(veth_netns):
    dst = veth_netns["host_ip"]
    assert port_closed_in_netns(veth_netns["ns"], dst, TARGET_PORT)
