import subprocess

import pytest
from conftest import wait_for_trace


def ping(dst_ip):
    cmd = ["ping", "-c1", "-W1", dst_ip]
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    print(f"Command output:\n{result.stdout}")
    if result.stderr:
        print(f"Command stderr:\n{result.stderr}")


@pytest.mark.usefixtures("loader")
def test_icmp_printk():
    dst = "127.0.0.1"
    ping(dst)
    assert wait_for_trace("Hello ping", timeout=5.0)
