"""Shared fixtures for the bisocket test suite.

Every test drives a real Server over a real loopback socket. The library's whole
job is what happens between two sockets, so the failures these tests cover --
a thread dying, a reply never arriving, a callback firing for the wrong socket --
only exist end to end.
"""
import os
import socket
import sys
import threading
import time
import asyncio
import contextlib

import pytest

# Set before bisocket is imported so no test run depends on the developer's
# environment, and so the missing-key warning does not fire during collection.
os.environ.setdefault('CRYPTO_KEY', 'bisocket-test-key')

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def free_port() -> int:
    """Pick a port the OS is currently willing to hand out."""
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_until_listening(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return
        except OSError as e:
            last = e
            time.sleep(0.05)
    raise RuntimeError(f'server on port {port} never started listening: {last}')


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.02) -> bool:
    """Poll `predicate` until it is true or `timeout` elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@contextlib.contextmanager
def running_server(server, port: int):
    """Run `server.start()` in a daemon thread and wait until it accepts."""
    threading.Thread(target=server.start, daemon=True).start()
    wait_until_listening(port)
    yield server


@contextlib.contextmanager
def running_async_server(server, port: int):
    """Run `server.astart()` on its own event loop in a daemon thread."""
    threading.Thread(target=lambda: asyncio.run(server.astart()), daemon=True).start()
    wait_until_listening(port)
    yield server


@pytest.fixture
def port() -> int:
    return free_port()


@pytest.fixture
def thread_errors():
    """Record exceptions that escape a bare thread.

    A server thread dying is invisible from the test's own thread -- the symptom
    is only that nothing happens afterwards. This turns it into an assertion.
    """
    captured = []
    original = threading.excepthook

    def hook(args):
        captured.append(args)
        original(args)

    threading.excepthook = hook
    try:
        yield captured
    finally:
        threading.excepthook = original
