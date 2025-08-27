import os
import shutil
import signal
import subprocess
import time

import pytest
from utils.trace_buffer import TraceBuffer


def require_cmd(cmd):
    return shutil.which(cmd) is not None


@pytest.fixture(scope="session")
def require_root():
    if os.geteuid() != 0:
        pytest.fail("root required")


@pytest.fixture()
def loader():
    bin_path = os.path.abspath(os.path.join(os.getcwd(), "build", "knock"))
    if not os.path.exists(bin_path):
        pytest.fail(f"bin_path missing: {bin_path}")

    trace_buffer.start_reading()
    trace_buffer.clear()

    proc = subprocess.Popen([bin_path, "lo", "6666", "1111", "2222", "3333"])
    time.sleep(0.5)
    yield proc
    trace_buffer.print_trace()
    try:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:
        proc.kill()

    trace_buffer.stop_reading()
    trace_buffer.clear()


trace_buffer = TraceBuffer()


def wait_for_trace(pattern):
    """Wait for a pattern in the trace buffer"""
    return trace_buffer.wait_for_pattern(pattern)
