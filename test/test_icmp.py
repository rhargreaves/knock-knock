import subprocess

import pytest
from conftest import wait_for_trace


def ping_in_netns(netns, dst_ip):
    cmd = ["ip", "netns", "exec", netns, "ping", "-c1", "-W1", dst_ip]
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    print(f"Command output:\n{result.stdout}")
    if result.stderr:
        print(f"Command stderr:\n{result.stderr}")


@pytest.mark.usefixtures("loader")
def test_icmp_printk(veth_netns):
    dst = veth_netns["host_ip"]
    ping_in_netns(veth_netns["ns"], dst)
    assert wait_for_trace("Hello ping", timeout=5.0)
