import fcntl
import os
import select
import time


class TraceBuffer:
    def __init__(self):
        self.lines = []
        self.trace_file = None
        self.poller = None

    def start_reading(self):
        """Initialize trace reading"""
        path = "/sys/kernel/debug/tracing/trace_pipe"
        if not os.path.exists(path):
            print("Warning: trace_pipe not found")
            return
        try:
            self.trace_file = open(path)

            # Make the file descriptor non-blocking
            fd = self.trace_file.fileno()
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Create a poller for the file
            self.poller = select.poll()
            self.poller.register(fd, select.POLLIN)

            # Read any immediately available data
            self._read_available_lines(timeout_ms=0)
            print("Trace reading initialized")
        except Exception as e:
            print(f"Error initializing trace reading: {e}")

    def stop_reading(self):
        """Cleanup trace reading"""
        if self.trace_file:
            self.trace_file.close()
            self.trace_file = None
        self.poller = None

    def print_trace(self):
        """Print the trace buffer"""
        self._read_available_lines(timeout_ms=0)
        for line in self.lines:
            print(f"  {line}")

    def clear(self):
        """Clear the trace buffer"""
        self.lines.clear()
        print("Trace buffer cleared")

    def _read_available_lines(self, timeout_ms=100):
        """Read any available trace lines with optional timeout"""
        if not self.trace_file or not self.poller:
            return

        def read_immediate():
            """Read all immediately available lines"""
            try:
                while True:
                    line = self.trace_file.readline()
                    if not line:
                        break
                    line = line.strip()
                    if line:
                        self.lines.append(line)
            except OSError:
                pass

        # First, read any immediately available data
        read_immediate()

        # Then wait for additional data if timeout is specified
        if timeout_ms > 0:
            # Use small polls in a loop to catch multiple quick messages
            end_time = time.time() + (timeout_ms / 1000.0)
            while time.time() < end_time:
                events = self.poller.poll(50)  # 50ms polls
                if events:
                    read_immediate()
                    # Keep reading for a bit more to catch follow-up messages
                    time.sleep(0.01)
                else:
                    time.sleep(0.01)

    def wait_for_pattern(self, pattern, timeout=1.0):
        """Wait for a pattern to appear in trace lines"""
        deadline = time.time() + timeout

        # Initial read with longer timeout to catch any immediate traces
        self._read_available_lines()

        while time.time() < deadline:
            # Check if pattern is already in existing lines
            for line in self.lines:
                if pattern in line:
                    print(f"Found pattern '{pattern}' in: {line}")
                    return True

            # Read more lines with a reasonable timeout
            self._read_available_lines(timeout_ms=50)
            time.sleep(0.1)  # Brief pause between checks

        print(f"Pattern '{pattern}' not found within {timeout}s")
        print("Available trace:")
        for line in self.lines:
            print(f"  {line}")
        return False

    def has_pattern(self, pattern):
        """Check if pattern exists in current buffer (reads new data first)"""
        self._read_available_lines()
        for line in self.lines:
            if pattern in line:
                return True
        return False

    def get_lines(self):
        """Get copy of all current trace lines (reads new data first)"""
        self._read_available_lines(timeout_ms=0)
        return self.lines.copy()
