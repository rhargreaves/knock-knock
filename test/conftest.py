import os
import select
import shutil
import signal
import subprocess
import time

import pytest


def require_cmd(cmd):
    return shutil.which(cmd) is not None


@pytest.fixture(scope="session")
def require_root():
    if os.geteuid() != 0:
        pytest.fail("root required")


@pytest.fixture()
def loader():
    bin_path = os.path.abspath(os.path.join(os.getcwd(), "build", "ping"))
    if not os.path.exists(bin_path):
        pytest.skip("build/ping missing")
    proc = subprocess.Popen([bin_path, "lo"])
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
    clear_trace()


def clear_trace():
    path = "/sys/kernel/debug/tracing/trace_pipe"
    if not os.path.exists(path):
        return
    with open(path, "w") as f:
        print("Clearing trace")
        f.write("")


def wait_for_trace(pattern, timeout=5.0):
    time.sleep(5)
    path = "/sys/kernel/debug/tracing/trace_pipe"
    if not os.path.exists(path):
        return False
    deadline = time.time() + timeout
    with open(path) as f:
        fd = f.fileno()
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        while time.time() < deadline:
            timeout_ms = int(max(0.0, deadline - time.time()) * 1000)
            events = poller.poll(timeout_ms)
            if not events:
                continue
            line = f.readline()
            print(f"line: {line}")
            if not line:
                continue
            if pattern in line:
                return True
    return False
