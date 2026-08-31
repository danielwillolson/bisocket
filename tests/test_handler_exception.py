"""Issue 1: a handler raising must not destroy the client connection.

Before the fix, an exception from `handler` escaped the per-request loop in
`Server.handle_client`: the thread died, the failing request was never answered,
and every later request on that client hit a broken pipe.
"""
import asyncio
import threading

import pytest

import bisocket
from bisocket import Client, Server, ENCRYPTION_FASTER

from conftest import running_server, running_async_server, wait_for

# Names added by the fix are looked up at call time, not at import time, so the
# tests that assert on *behaviour* still run -- and fail on that behaviour --
# against a build that predates the new API.


def _handler(request):
    if request.method == 'boom':
        raise ValueError('handler blew up')
    request.send_data(b'ok:' + request.data)


def test_handler_exception_does_not_kill_the_connection(port, thread_errors):
    received = {}
    server = Server('127.0.0.1', port, _handler, encryption=ENCRYPTION_FASTER)

    with running_server(server, port):
        with Client('127.0.0.1', port,
                    lambda m: received.__setitem__(m.request_id, m),
                    encryption=ENCRYPTION_FASTER) as client:
            failing = client.send_obj('boom', 'b')
            assert wait_for(lambda: failing in received), \
                'a request whose handler raised was never answered'

            # The connection must still carry unrelated traffic afterwards.
            ok = client.send_obj('fine', 'c')
            assert wait_for(lambda: ok in received), \
                'a later request died with the connection'
            assert received[ok].data == b'ok:"c"'

    assert not thread_errors, \
        f'handler exception escaped into the server thread: {thread_errors}'


def test_error_reply_is_distinguishable_from_a_normal_reply(port):
    received = {}
    server = Server('127.0.0.1', port, _handler, encryption=ENCRYPTION_FASTER)

    with running_server(server, port):
        with Client('127.0.0.1', port,
                    lambda m: received.__setitem__(m.request_id, m),
                    encryption=ENCRYPTION_FASTER) as client:
            failing = client.send_obj('boom', 'b')
            ok = client.send_obj('fine', 'c')
            assert wait_for(lambda: failing in received and ok in received)

    failed = received[failing]
    assert failed.is_error
    assert failed.error.type == 'ValueError'
    assert failed.error.message == 'handler blew up'
    assert failed.error.method == 'boom'

    with pytest.raises(bisocket.HandlerError) as excinfo:
        failed.raise_for_error()
    assert 'handler blew up' in str(excinfo.value)
    assert excinfo.value.info.type == 'ValueError'

    # An ordinary reply must be untouched by any of this.
    assert not received[ok].is_error
    assert received[ok].error is None
    assert received[ok].raise_for_error() is received[ok]


def test_error_reply_is_ignorable_by_a_client_that_does_not_check(port):
    """The error frame rides inside the existing payload field.

    An older client knows nothing about is_error; it must still receive a
    well-formed Message on the right request_id rather than fail to parse.
    """
    received = {}
    server = Server('127.0.0.1', port, _handler, encryption=ENCRYPTION_FASTER)

    with running_server(server, port):
        with Client('127.0.0.1', port,
                    lambda m: received.__setitem__(m.request_id, m),
                    encryption=ENCRYPTION_FASTER) as client:
            failing = client.send_obj('boom', 'b')
            assert wait_for(lambda: failing in received)

    message = received[failing]
    assert message.request_id == failing
    assert isinstance(message.data, bytes)
    assert message.data.startswith(bisocket.main.HANDLER_ERROR_TOKEN)


def test_traceback_is_withheld_unless_asked_for(port):
    received = {}
    server = Server('127.0.0.1', port, _handler, encryption=ENCRYPTION_FASTER)

    with running_server(server, port):
        with Client('127.0.0.1', port,
                    lambda m: received.__setitem__(m.request_id, m),
                    encryption=ENCRYPTION_FASTER) as client:
            failing = client.send_obj('boom', 'b')
            assert wait_for(lambda: failing in received)

    assert received[failing].error.traceback is None


def test_traceback_is_sent_when_the_server_opts_in(port):
    received = {}
    server = Server('127.0.0.1', port, _handler,
                    encryption=ENCRYPTION_FASTER, send_error_traceback=True)

    with running_server(server, port):
        with Client('127.0.0.1', port,
                    lambda m: received.__setitem__(m.request_id, m),
                    encryption=ENCRYPTION_FASTER) as client:
            failing = client.send_obj('boom', 'b')
            assert wait_for(lambda: failing in received)

    tb = received[failing].error.traceback
    assert tb is not None
    assert 'ValueError: handler blew up' in tb


def test_every_failing_request_is_answered(port, thread_errors):
    """Several failures in a row, interleaved with successes."""
    received = {}
    server = Server('127.0.0.1', port, _handler, encryption=ENCRYPTION_FASTER)

    with running_server(server, port):
        with Client('127.0.0.1', port,
                    lambda m: received.__setitem__(m.request_id, m),
                    encryption=ENCRYPTION_FASTER) as client:
            ids = []
            for i in range(5):
                ids.append(('boom', client.send_obj('boom', i)))
                ids.append(('fine', client.send_obj('fine', i)))
            assert wait_for(lambda: all(r in received for _, r in ids))

    for kind, request_id in ids:
        assert received[request_id].is_error is (kind == 'boom')
    assert not thread_errors


def test_async_handler_exception_does_not_kill_the_connection(port, thread_errors):
    """The same guarantee on the asyncio server and client."""
    received = {}

    async def async_handler(request):
        if request.method == 'boom':
            raise ValueError('async handler blew up')
        request.send_data(b'ok:' + request.data)

    server = Server('127.0.0.1', port, async_handler, encryption=ENCRYPTION_FASTER)

    async def scenario():
        async with Client('127.0.0.1', port,
                          lambda m: received.__setitem__(m.request_id, m),
                          encryption=ENCRYPTION_FASTER) as client:
            failing = await client.asend_obj('boom', 'b')
            ok = await client.asend_obj('fine', 'c')
            for _ in range(500):
                if failing in received and ok in received:
                    break
                await asyncio.sleep(0.02)
            return failing, ok

    with running_async_server(server, port):
        failing, ok = asyncio.run(asyncio.wait_for(scenario(), 30))

    assert failing in received, 'the failing request was never answered'
    assert received[failing].is_error
    assert received[failing].error.type == 'ValueError'
    assert ok in received, 'a later request died with the connection'
    assert not received[ok].is_error
    assert not thread_errors
