"""Issue 2: `on_finally` fires once per socket, so it must say which socket.

A client holds two connections under one client_id. `on_open`/`on_close` are
send-socket events, but `on_finally` sits in the outer `finally` of
`handle_client` and therefore fires for both -- and the receive socket's turn
arrives *before* `on_close`. A server that allocates in `on_open` and frees in
`on_finally` frees while the client is still live.

The count is deliberately unchanged: `on_finally` still means "a connection
ended". What the fix adds is the ability to tell which one.
"""
import asyncio
import threading
import time

import bisocket
from bisocket import Client, Server, ENCRYPTION_FASTER

from conftest import running_server, running_async_server, wait_for


def _record(events, name):
    def callback(info):
        events.append((name, info))
    return callback


def _run_one_client(port, encryption=ENCRYPTION_FASTER):
    with Client('127.0.0.1', port, lambda m: None, encryption=encryption) as client:
        client.send_obj('echo', 'x')
        time.sleep(0.3)


def _client_finallys(events):
    """on_finally payloads for connections that got as far as identifying a client.

    running_server's readiness probe connects and drops without a handshake, and
    that connection legitimately produces its own on_finally with no client_id.
    """
    return [
        info for name, info in events
        if name == 'on_finally' and info.client_id is not None
    ]


def _server_with_all_callbacks(port, events):
    return Server(
        '127.0.0.1', port, lambda r: r.send_data(b'ok'),
        on_open=_record(events, 'on_open'),
        on_open_receive=_record(events, 'on_open_receive'),
        on_close=_record(events, 'on_close'),
        on_close_receive=_record(events, 'on_close_receive'),
        on_finally=_record(events, 'on_finally'),
        encryption=ENCRYPTION_FASTER,
    )


def test_on_finally_says_which_socket_it_is_for(port):
    events = []
    with running_server(_server_with_all_callbacks(port, events), port):
        _run_one_client(port)
        assert wait_for(lambda: len(_client_finallys(events)) == 2)

    finallys = _client_finallys(events)
    assert len(finallys) == 2, 'on_finally still fires once per socket'

    types = sorted(info.connection_type for info in finallys)
    assert types == [bisocket.CONNECTION_RECEIVE, bisocket.CONNECTION_SEND], (
        'the two on_finally calls are indistinguishable; a callback cannot tell '
        'the send socket ending from the receive socket ending'
    )

    # Both are the same client, which is what made them ambiguous.
    assert len({info.client_id for info in finallys}) == 1


def test_a_server_can_free_resources_on_the_send_socket_only(port):
    """The workaround this replaces: tracking send-socket liveness by hand."""
    events = []
    with running_server(_server_with_all_callbacks(port, events), port):
        _run_one_client(port)
        assert wait_for(lambda: len(_client_finallys(events)) == 2)

    send_finallys = [
        info for info in _client_finallys(events)
        if info.connection_type == bisocket.CONNECTION_SEND
    ]
    assert len(send_finallys) == 1, \
        'filtering on_finally to the send socket must leave exactly one per client'


def test_open_and_close_callbacks_carry_their_socket(port):
    events = []
    with running_server(_server_with_all_callbacks(port, events), port):
        _run_one_client(port)
        assert wait_for(lambda: len(_client_finallys(events)) == 2)

    by_name = {}
    for name, info in events:
        by_name.setdefault(name, []).append(info)

    assert by_name['on_open'][0].connection_type == bisocket.CONNECTION_SEND
    assert by_name['on_open_receive'][0].connection_type == bisocket.CONNECTION_RECEIVE
    assert by_name['on_close'][0].connection_type == bisocket.CONNECTION_SEND
    assert by_name['on_close_receive'][0].connection_type == bisocket.CONNECTION_RECEIVE


def test_the_receive_socket_on_finally_still_precedes_on_close(port):
    """Pin the documented ordering, since it is the surprising part.

    This is not a bug being fixed -- it is the behaviour the README now states,
    and the reason `connection_type` is needed rather than a reordering.
    """
    events = []
    with running_server(_server_with_all_callbacks(port, events), port):
        _run_one_client(port)
        assert wait_for(lambda: len(_client_finallys(events)) == 2)

    order = [
        (name, getattr(info, 'connection_type', None))
        for name, info in events
        if name in ('on_close', 'on_finally') and info.client_id is not None
    ]
    receive_finally = order.index(('on_finally', bisocket.CONNECTION_RECEIVE))
    send_close = order.index(('on_close', bisocket.CONNECTION_SEND))
    send_finally = order.index(('on_finally', bisocket.CONNECTION_SEND))

    assert receive_finally < send_close < send_finally


def test_callback_payloads_stay_constructible_the_old_way():
    """`connection_type` is additive: existing callbacks must keep working."""
    assert bisocket.OnOpenInfo('abc') == bisocket.OnOpenInfo('abc', None)
    assert bisocket.OnCloseInfo('abc').connection_type is None
    assert bisocket.OnFinallyInfo(None).connection_type is None

    # Positional construction with the new field is also supported.
    info = bisocket.OnFinallyInfo('abc', bisocket.CONNECTION_SEND)
    assert (info.client_id, info.connection_type) == ('abc', 'send')


def test_connection_type_is_none_when_the_handshake_never_identified_the_socket(port):
    """A socket that connects and vanishes cannot be attributed to either side."""
    import socket as socket_module

    events = []
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'ok'),
                    on_finally=_record(events, 'on_finally'),
                    encryption=ENCRYPTION_FASTER)

    with running_server(server, port):
        # running_server's own readiness probe already opened and dropped a
        # connection; do it once more explicitly so the intent is on the page.
        with socket_module.create_connection(('127.0.0.1', port), timeout=2):
            pass
        assert wait_for(lambda: len(events) >= 1)

    anonymous = [info for _, info in events if info.client_id is None]
    assert anonymous, 'a connection that never identified itself produced no on_finally'
    assert all(info.connection_type is None for info in anonymous)


def test_async_server_callbacks_carry_their_socket(port):
    events = []
    server = _server_with_all_callbacks(port, events)

    async def scenario():
        async with Client('127.0.0.1', port, lambda m: None,
                          encryption=ENCRYPTION_FASTER) as client:
            await client.asend_obj('echo', 'x')
            await asyncio.sleep(0.3)

    with running_async_server(server, port):
        asyncio.run(asyncio.wait_for(scenario(), 30))
        assert wait_for(lambda: len(_client_finallys(events)) == 2)

    finallys = _client_finallys(events)
    assert sorted(i.connection_type for i in finallys) == \
        [bisocket.CONNECTION_RECEIVE, bisocket.CONNECTION_SEND]
