"""Issue 4: a mode mismatch is diagnosed well but must also be *reported* well.

`_mismatch_message()` never reached anyone: on the server it escaped
`handle_client` as an unhandled thread traceback (a `ValueError` is neither
`ConnectionClosed` nor `OSError`), and the client only ever saw
"Connection closed after 0 byte(s) of an incomplete frame".
"""
import asyncio
import time

import pytest

import bisocket
from bisocket import Client, Server, ENCRYPTION_SECURE, ENCRYPTION_FASTER, ENCRYPTION_OFF

from conftest import running_server, running_async_server, wait_for, free_port


MISMATCHED_PAIRS = [
    (ENCRYPTION_SECURE, ENCRYPTION_FASTER),
    (ENCRYPTION_FASTER, ENCRYPTION_SECURE),
    (ENCRYPTION_SECURE, ENCRYPTION_OFF),
    (ENCRYPTION_OFF, ENCRYPTION_SECURE),
    (ENCRYPTION_FASTER, ENCRYPTION_OFF),
    (ENCRYPTION_OFF, ENCRYPTION_FASTER),
]


@pytest.mark.parametrize('server_mode,client_mode', MISMATCHED_PAIRS)
def test_the_client_is_told_it_is_an_encryption_mismatch(port, server_mode, client_mode):
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'ok'),
                    encryption=server_mode)

    with running_server(server, port):
        with pytest.raises(bisocket.EncryptionMismatch) as excinfo:
            with Client('127.0.0.1', port, lambda m: None, encryption=client_mode):
                pass

    text = str(excinfo.value)
    assert 'encryption' in text.lower(), \
        f'the client was told nothing about encryption: {text!r}'


@pytest.mark.parametrize('server_mode,client_mode', MISMATCHED_PAIRS)
def test_the_message_names_both_modes(port, server_mode, client_mode):
    """"server is 'secure', you are 'faster'" beats "connection closed"."""
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'ok'),
                    encryption=server_mode)

    with running_server(server, port):
        with pytest.raises(bisocket.EncryptionMismatch) as excinfo:
            with Client('127.0.0.1', port, lambda m: None, encryption=client_mode):
                pass

    text = str(excinfo.value)
    assert repr(server_mode) in text, f'server mode missing from: {text!r}'
    assert repr(client_mode) in text, f'client mode missing from: {text!r}'


def test_the_server_does_not_raise_an_unhandled_thread_exception(port, thread_errors):
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'ok'),
                    encryption=ENCRYPTION_SECURE)

    with running_server(server, port):
        with pytest.raises(bisocket.EncryptionMismatch):
            with Client('127.0.0.1', port, lambda m: None, encryption=ENCRYPTION_FASTER):
                pass

    assert not thread_errors, (
        'the mismatch escaped handle_client as an unhandled thread traceback: '
        f'{[e.exc_value for e in thread_errors]}'
    )


def test_the_server_logs_one_clean_line(port, capsys):
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'ok'),
                    encryption=ENCRYPTION_SECURE)

    with running_server(server, port):
        with pytest.raises(bisocket.EncryptionMismatch):
            with Client('127.0.0.1', port, lambda m: None, encryption=ENCRYPTION_FASTER):
                pass
        # The server logs from its own thread; give it a moment to get there.
        time.sleep(0.5)

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert 'Rejected connection' in combined, \
        f'the server never said why it rejected the connection:\n{combined}'
    assert 'Traceback (most recent call last)' not in combined, \
        f'the mismatch was reported as a traceback:\n{combined}'


def test_a_mismatch_does_not_take_down_the_server(port):
    """One misconfigured client must not stop the next correct one."""
    received = {}
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'served:' + r.data),
                    encryption=ENCRYPTION_SECURE)

    with running_server(server, port):
        with pytest.raises(bisocket.EncryptionMismatch):
            with Client('127.0.0.1', port, lambda m: None, encryption=ENCRYPTION_FASTER):
                pass

        with Client('127.0.0.1', port,
                    lambda m: received.__setitem__(m.request_id, m),
                    encryption=ENCRYPTION_SECURE) as client:
            request_id = client.send_obj('echo', 'still here')
            assert wait_for(lambda: request_id in received)
            assert received[request_id].data == b'served:"still here"'


@pytest.mark.parametrize('mode', [ENCRYPTION_SECURE, ENCRYPTION_FASTER, ENCRYPTION_OFF])
def test_matching_modes_are_unaffected(mode):
    """The check must not fire on a connection that is perfectly fine."""
    received = {}
    port = free_port()
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'ok:' + r.data),
                    encryption=mode)
    with running_server(server, port):
        with Client('127.0.0.1', port,
                    lambda m: received.__setitem__(m.request_id, m),
                    encryption=mode) as client:
            request_id = client.send_obj('echo', mode)
            assert wait_for(lambda: request_id in received)
            assert received[request_id].data == b'ok:"%s"' % mode.encode()


def test_the_handshake_frame_the_client_sends_is_unchanged(port):
    """The diagnosis is carried by the server's *reply*, not by extra request bytes.

    Nothing was added to what a client writes, so a client built from this
    revision still talks to a server that predates it exactly as before.
    """
    from bisocket.main import SPLIT_TOKEN, END_TOKEN

    client = Client('127.0.0.1', port, lambda m: None, encryption=ENCRYPTION_OFF)
    frame = client.encrypt(SPLIT_TOKEN.join([b'receive', client.client_id.encode()]))

    # PlaintextCodec's own one-byte tag is pre-existing; past it, the frame is
    # exactly the two handshake fields and nothing else.
    assert frame[1:] == SPLIT_TOKEN.join([b'receive', client.client_id.encode()])
    assert not frame.startswith(bisocket.main.HANDSHAKE_ERROR_TOKEN)


def test_a_server_reply_that_is_not_an_error_is_not_mistaken_for_one(port):
    from bisocket.main import check_handshake_error

    # An ordinary 'ok' ack, and random ciphertext, must both pass through.
    check_handshake_error(b'ok', ENCRYPTION_SECURE)
    check_handshake_error(b'BZh91AY&SY', ENCRYPTION_SECURE)
    check_handshake_error(b'', ENCRYPTION_FASTER)


def test_async_server_reports_a_mismatch_the_same_way(port, thread_errors):
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'ok'),
                    encryption=ENCRYPTION_SECURE)

    async def scenario():
        async with Client('127.0.0.1', port, lambda m: None,
                          encryption=ENCRYPTION_FASTER):
            pass

    with running_async_server(server, port):
        with pytest.raises(bisocket.EncryptionMismatch) as excinfo:
            asyncio.run(asyncio.wait_for(scenario(), 30))

    text = str(excinfo.value)
    assert repr(ENCRYPTION_SECURE) in text and repr(ENCRYPTION_FASTER) in text
    assert not thread_errors


def test_async_client_against_a_sync_server(port):
    server = Server('127.0.0.1', port, lambda r: r.send_data(b'ok'),
                    encryption=ENCRYPTION_OFF)

    async def scenario():
        async with Client('127.0.0.1', port, lambda m: None,
                          encryption=ENCRYPTION_SECURE):
            pass

    with running_server(server, port):
        with pytest.raises(bisocket.EncryptionMismatch) as excinfo:
            asyncio.run(asyncio.wait_for(scenario(), 30))

    assert repr(ENCRYPTION_OFF) in str(excinfo.value)


def test_encryption_mismatch_is_still_a_value_error():
    """Code written against the old `raise ValueError(...)` must keep working."""
    assert issubclass(bisocket.EncryptionMismatch, ValueError)
