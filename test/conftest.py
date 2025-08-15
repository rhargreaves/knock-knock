import os
import time
import uuid
import select
import signal
import shutil
import pytest
import subprocess


def require_cmd(cmd):
    return shutil.which(cmd) is not None


@pytest.fixture(scope="session")
def require_root():
    if os.geteuid() != 0:
        pytest.fail("root required")


@pytest.fixture(scope="session")
def veth_netns(require_root):
    ns = f"knockns-{uuid.uuid4().hex[:6]}"
    veth_host = f"vethh-{uuid.uuid4().hex[:6]}"
    veth_ns = f"vethn-{uuid.uuid4().hex[:6]}"
    host_ip = "10.0.0.1/24"
    ns_ip = "10.0.0.2/24"
    if not require_cmd("ip"):
        pytest.skip("ip required")
    try:
        subprocess.run(["ip", "netns", "add", ns], check=True)
        subprocess.run(["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_ns], check=True)
        subprocess.run(["ip", "link", "set", veth_ns, "netns", ns], check=True)
        subprocess.run(["ip", "addr", "add", host_ip, "dev", veth_host], check=True)
        subprocess.run(["ip", "link", "set", veth_host, "up"], check=True)
        subprocess.run(["ip", "netns", "exec", ns, "ip", "addr", "add", ns_ip, "dev", veth_ns], check=True)
        subprocess.run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"], check=True)
        subprocess.run(["ip", "netns", "exec", ns, "ip", "link", "set", veth_ns, "up"], check=True)
        yield {"ns": ns, "veth_host": veth_host, "veth_ns": veth_ns, "host_ip": "10.0.0.1", "ns_ip": "10.0.0.2"}
    finally:
        subprocess.run(["ip", "link", "del", veth_host], check=False)
        subprocess.run(["ip", "netns", "del", ns], check=False)


@pytest.fixture()
def loader(veth_netns):
    bin_path = os.path.abspath(os.path.join(os.getcwd(), "build", "ping"))
    if not os.path.exists(bin_path):
        pytest.skip("build/ping missing")
    print(f"veth_netns: {veth_netns}")
    proc = subprocess.Popen([bin_path, veth_netns["veth_host"]])
    time.sleep(1)
    yield proc
    try:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:
        proc.kill()


def wait_for_trace(pattern, timeout=5.0):
    path = "/sys/kernel/debug/tracing/trace_pipe"
    if not os.path.exists(path):
        return False
    deadline = time.time() + timeout
    with open(path, "r") as f:
        fd = f.fileno()
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        while time.time() < deadline:
            timeout_ms = int(max(0.0, deadline - time.time()) * 1000)
            events = poller.poll(timeout_ms)
            if not events:
                continue
            line = f.readline()
            if not line:
                continue
            if pattern in line:
                return True
    return False
