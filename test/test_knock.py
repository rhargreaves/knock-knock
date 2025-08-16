import subprocess

import pytest

TARGET_PORT = 6666


def port_filtered_in_netns(netns, dst_ip, port):
    cmd = [
        "ip",
        "netns",
        "exec",
        netns,
        "nc",
        "-zvw",
        "2",
        dst_ip,
        str(port),
    ]
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


def port_closed_in_netns(netns, dst_ip, port):
    cmd = ["ip", "netns", "exec", netns, "nc", "-z", dst_ip, str(port)]
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"Command output:\n{result.stdout}")
    if result.stderr:
        print(f"Command stderr:\n{result.stderr}")
    return result.returncode == 1


@pytest.mark.usefixtures("loader")
def test_port_filtered_by_default(veth_netns):
    dst = veth_netns["host_ip"]
    assert port_filtered_in_netns(veth_netns["ns"], dst, TARGET_PORT)
