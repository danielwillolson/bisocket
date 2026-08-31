import os
import sys
import bz2
import base64
import uuid
import time
import json
import socket
import inspect
import asyncio
import weakref
import traceback
import threading
import queue
from typing import Callable, Awaitable, Any
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


VERSION = '0.0.8'
END_TOKEN = b'|[-_-]|'
SPLIT_TOKEN = b'|(---)|'
SPLIT_TOKEN2 = b'|{***}|'
LENGTH_OF_END_TOKEN = len(END_TOKEN)
RECV_SIZE = 65536
CLIENT_TEARDOWN_TIMEOUT = 30.0
DEFAULT_CRYPTO_KEY = 'secret-lol'
SHUTDOWN_TIMEOUT = 5.0

# AES-GCM nonce length. Fixed, so the 'faster' wire format can put the nonce at a
# known offset instead of paying for a delimiter that random bytes might contain.
IV_LENGTH = 12

# How much work every frame goes through on its way to the socket. A Client and a
# Server have to agree: the three formats are not interchangeable.
ENCRYPTION_SECURE = 'secure'   # AES-GCM, then bz2 -- the original 0.0.8 format
ENCRYPTION_FASTER = 'faster'   # AES-GCM only
ENCRYPTION_OFF = 'off'         # no encryption at all

ENCRYPTION_MODES = (ENCRYPTION_SECURE, ENCRYPTION_FASTER, ENCRYPTION_OFF)

_ENCRYPTION_ALIASES = {
    ENCRYPTION_SECURE: ENCRYPTION_SECURE,
    'on': ENCRYPTION_SECURE, 'true': ENCRYPTION_SECURE, '1': ENCRYPTION_SECURE,
    'yes': ENCRYPTION_SECURE, 'default': ENCRYPTION_SECURE, 'bz2': ENCRYPTION_SECURE,
    ENCRYPTION_FASTER: ENCRYPTION_FASTER,
    'fast': ENCRYPTION_FASTER, 'fastest': ENCRYPTION_FASTER,
    'nocompress': ENCRYPTION_FASTER, 'no-compress': ENCRYPTION_FASTER,
    ENCRYPTION_OFF: ENCRYPTION_OFF,
    'none': ENCRYPTION_OFF, 'false': ENCRYPTION_OFF, '0': ENCRYPTION_OFF,
    'no': ENCRYPTION_OFF, 'plaintext': ENCRYPTION_OFF, 'plain': ENCRYPTION_OFF,
    'insecure': ENCRYPTION_OFF, 'disabled': ENCRYPTION_OFF,
}


class ConnectionClosed(ConnectionError):
    """The peer went away before a complete frame arrived."""


# A single recv() can return more than one frame, and the bytes past the first
# END_TOKEN belong to the next frame. They are kept per connection so the next
# receive() picks up where this one stopped instead of discarding them.
_recv_buffers: 'weakref.WeakKeyDictionary[socket.socket, bytes]' = weakref.WeakKeyDictionary()


def _split_frame(conn: socket.socket, buffer: bytes) -> bytes | None:
    """Return the first complete frame in `buffer`, stashing the remainder."""
    index = buffer.find(END_TOKEN)
    if index == -1:
        return None
    _recv_buffers[conn] = buffer[index + LENGTH_OF_END_TOKEN:]
    return buffer[:index]


def receive(conn: socket.socket) -> bytes:
    buffer = _recv_buffers.get(conn, b'')

    while True:
        frame = _split_frame(conn, buffer)
        if frame is not None:
            return frame

        chunk = conn.recv(RECV_SIZE)
        if not chunk:
            _recv_buffers.pop(conn, None)
            raise ConnectionClosed(f'Connection closed after {len(buffer)} byte(s) of an incomplete frame')
        buffer += chunk


_crypto_key_warned = False


def get_crypto_key() -> str:
    """Read CRYPTO_KEY, warning once if the insecure development default is used."""
    global _crypto_key_warned

    key = os.environ.get('CRYPTO_KEY')
    if key:
        return key

    if not _crypto_key_warned:
        _crypto_key_warned = True
        print(
            'WARNING: CRYPTO_KEY is not set, falling back to the default insecure key. '
            'Set CRYPTO_KEY before using bisocket outside of local development.',
            file=sys.stderr,
        )
    return DEFAULT_CRYPTO_KEY


def resolve_encryption(mode: 'str | bool | None' = None) -> str:
    """Normalise an encryption mode, falling back to $BISOCKET_ENCRYPTION.

    Accepts a canonical name ('secure', 'faster', 'off'), a bool, or one of the
    aliases in _ENCRYPTION_ALIASES. None means 'not specified here', so the
    environment decides; unset environment means the secure default.
    """
    if mode is None:
        mode = os.environ.get('BISOCKET_ENCRYPTION')
    if mode is None or mode == '':
        return ENCRYPTION_SECURE
    if isinstance(mode, bool):
        return ENCRYPTION_SECURE if mode else ENCRYPTION_OFF

    try:
        return _ENCRYPTION_ALIASES[str(mode).strip().lower()]
    except KeyError:
        raise ValueError(
            f'unknown encryption mode {mode!r}; expected one of {", ".join(ENCRYPTION_MODES)}'
        ) from None


def send(conn: socket.socket, data: bytes) -> None:
    conn.sendall(data+END_TOKEN)


async def async_receive(sock: socket.socket) -> bytes:
    loop = asyncio.get_running_loop()
    buffer = _recv_buffers.get(sock, b'')

    while True:
        frame = _split_frame(sock, buffer)
        if frame is not None:
            return frame

        chunk = await loop.sock_recv(sock, RECV_SIZE)
        if not chunk:
            _recv_buffers.pop(sock, None)
            raise ConnectionClosed(f'Connection closed after {len(buffer)} byte(s) of an incomplete frame')
        buffer += chunk


async def async_send(sock: socket.socket, data: bytes) -> None:
    loop = asyncio.get_running_loop()
    await loop.sock_sendall(sock, data + END_TOKEN)


def compress_bytes(data):
    return bz2.compress(data, compresslevel=9)


def decompress_bytes(data):
    return bz2.decompress(data)


@dataclass
class CompressedEncryptedData:
    data: bytes
    iv: bytes

    def to_dict(self) -> dict:
        return {
            'data': list(self.data),  # .hex(),
            'iv': list(self.iv),  # .hex(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    def to_bytes(self) -> bytes:
        return compress_bytes(self.to_json().encode())
    
    @classmethod
    def from_dict(cls, data: dict) -> 'CompressedEncryptedData':
        return cls(
            data=bytes(data['data']),
            iv=bytes(data['iv']),
        )
    
    @classmethod
    def from_json(cls, data: str) -> 'CompressedEncryptedData':
        return cls.from_dict(json.loads(data))
    
    def encrypted_data(self) -> 'EncryptedData':
        return EncryptedData(
            data=decompress_bytes(self.data),
            iv=decompress_bytes(self.iv),
        )
    

@dataclass
class EncryptedData:
    data: bytes
    iv: bytes

    def to_dict(self) -> dict:
        return {
            'data': list(self.data),  # .hex(),
            'iv': list(self.iv),  # .hex(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    def to_bytes(self) -> bytes:
        return compress_bytes(SPLIT_TOKEN2.join([self.data, self.iv]))
    
    @classmethod
    def from_dict(cls, data: dict) -> 'EncryptedData':
        return cls(
            data=bytes(data['data']),
            iv=bytes(data['iv']),
        )
    
    @classmethod
    def from_json(cls, data: str) -> 'EncryptedData':
        return cls.from_dict(json.loads(data))
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedData':
        data, iv = decompress_bytes(data).rsplit(SPLIT_TOKEN2, 1)
        return cls(
            data=data,
            iv=iv,
        )
    
    def compress_data(self) -> 'CompressedEncryptedData':
        return CompressedEncryptedData(
            data=compress_bytes(self.data),
            iv=compress_bytes(self.iv),
        )

    @classmethod
    def decompress_data(cls, data: 'CompressedEncryptedData') -> 'EncryptedData':
        return EncryptedData(
            data=decompress_bytes(data.data),
            iv=decompress_bytes(data.iv),
        )


class EncryptionService:
    def __init__(self, key_string: str):
        self.key = self.derive_key(key_string)
        self.aesgcm = AESGCM(self.key)

    @staticmethod
    def derive_key(key_string: str) -> bytes:
        """Derive a 32-byte key from the input string using SHA-256"""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key_string.encode())
        return digest.finalize()

    def encrypt_obj(self, obj: dict) -> EncryptedData:
        """Encrypt data using AES-GCM"""
        # Convert data to JSON string and encode
        data_bytes = json.dumps(obj).encode()

        return self.encrypt_data(data_bytes)

    def decrypt_obj(self, encrypted_data: EncryptedData) -> dict:
        """Decrypt data using AES-GCM"""
        return json.loads(self.decrypt_data(encrypted_data).decode())

    def encrypt_data(self, data: bytes) -> EncryptedData:
        """Encrypt data using AES-GCM"""
        # Generate 12-byte IV
        iv = os.urandom(IV_LENGTH)

        # Encrypt data (includes auth tag automatically)
        encrypted = self.aesgcm.encrypt(iv, data, None)

        return EncryptedData(encrypted, iv)

    def decrypt_data(self, encrypted_data: EncryptedData) -> bytes:
        """Decrypt data using AES-GCM"""
        try:
            # Decrypt data
            decrypted_bytes = self.aesgcm.decrypt(encrypted_data.iv, encrypted_data.data, None)

            # Parse JSON data
            return decrypted_bytes  # json.loads(decrypted_bytes.decode())
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise ValueError("Failed to decrypt data")


class SecureCodec:
    """AES-GCM, then bz2. The original format, kept as the default so a 0.0.9
    peer still talks to a 0.0.8 one.

    The bz2 pass runs *after* encryption, so it is compressing ciphertext -- which
    is incompressible. It costs a lot of CPU per frame and saves almost nothing.
    'faster' exists to skip it.
    """

    mode = ENCRYPTION_SECURE
    encrypts = True
    offload = True  # bz2 at level 9 is slow enough to be worth a thread hop

    def __init__(self, key_string: str):
        self.encryption_service = EncryptionService(key_string)

    def encode(self, data: bytes) -> bytes:
        return self.encryption_service.encrypt_data(data).to_bytes()

    def decode(self, data: bytes) -> bytes:
        try:
            encrypted_data = EncryptedData.from_bytes(data)
        except Exception as e:
            raise ValueError(_mismatch_message(self.mode)) from e
        return self.encryption_service.decrypt_data(encrypted_data)


class FasterCodec(SecureCodec):
    """AES-GCM with no compression: same confidentiality, much less CPU.

    The nonce goes in front of the ciphertext at a fixed offset rather than behind
    a delimiter, because both halves are random bytes and could contain any
    delimiter we picked.
    """

    mode = ENCRYPTION_FASTER
    encrypts = True
    offload = False  # AES-GCM is hardware-accelerated; a thread hop costs more

    def encode(self, data: bytes) -> bytes:
        encrypted = self.encryption_service.encrypt_data(data)
        return encrypted.iv + encrypted.data

    def decode(self, data: bytes) -> bytes:
        if len(data) < IV_LENGTH:
            raise ValueError(_mismatch_message(self.mode))
        encrypted_data = EncryptedData(data[IV_LENGTH:], data[:IV_LENGTH])
        return self.encryption_service.decrypt_data(encrypted_data)


class PlaintextCodec:
    """No encryption. For trusted networks only -- anything on the path can read
    and modify every frame.

    Payloads are arbitrary caller bytes, so one containing END_TOKEN would be cut
    into two bogus frames by the reader. The other modes get away with ignoring
    that because their output is ciphertext, but plaintext really can contain it.

    Rather than encode every frame, each one is tagged with a single byte saying
    how it was written: almost always _RAW, which passes the payload through
    untouched, and _B64 for the rare frame that does contain END_TOKEN (base64 has
    no '|', so the token cannot survive). The check is one substring scan at
    memory speed, so the common path stays free of both the 33% base64 growth and
    the extra pass over the buffer.
    """

    mode = ENCRYPTION_OFF
    encrypts = False
    offload = False
    encryption_service = None

    _RAW = b'r'
    _B64 = b'b'

    def encode(self, data: bytes) -> bytes:
        if END_TOKEN in data:
            return self._B64 + base64.b64encode(data)
        return self._RAW + data

    def decode(self, data: bytes) -> bytes:
        tag, payload = data[:1], data[1:]
        if tag == self._RAW:
            return payload
        if tag == self._B64:
            try:
                return base64.b64decode(payload, validate=True)
            except Exception as e:
                raise ValueError(_mismatch_message(self.mode)) from e
        raise ValueError(_mismatch_message(self.mode))


_CODECS = {
    ENCRYPTION_SECURE: SecureCodec,
    ENCRYPTION_FASTER: FasterCodec,
    ENCRYPTION_OFF: PlaintextCodec,
}


def _mismatch_message(mode: str) -> str:
    return (
        f'could not read frame as {mode!r}. A Client and a Server must use the '
        f'same encryption mode -- check that both set the same value (one of '
        f'{", ".join(ENCRYPTION_MODES)}) via the encryption= argument or '
        f'$BISOCKET_ENCRYPTION.'
    )


_insecure_warned = False


def build_codec(encryption: 'str | bool | None' = None):
    """Return the codec for `encryption`, warning once if it disables encryption."""
    global _insecure_warned

    mode = resolve_encryption(encryption)
    if mode == ENCRYPTION_OFF:
        if not _insecure_warned:
            _insecure_warned = True
            print(
                'WARNING: bisocket encryption is off; frames are sent in plaintext. '
                'Only do this on a trusted private network.',
                file=sys.stderr,
            )
        return PlaintextCodec()

    # get_crypto_key() is only consulted when a key is actually needed, so the
    # missing-CRYPTO_KEY warning stays quiet when encryption is off.
    return _CODECS[mode](get_crypto_key())


@dataclass
class Message:
    request_id: str
    data: bytes

    def get_str(self) -> str:
        return self.data.decode()
    
    def get_obj(self) -> dict | list | int | float | bool | str | None:
        return json.loads(self.get_str())


class Client:
    def __init__(
            self, 
            host: str, 
            port: int, 
            on_receive: Callable[[Message], Awaitable[None] | None],
            encryption: str | bool | None = None,
        ) -> None:
        # Initialize encryption service
        self.client_id = str(uuid.uuid4())

        # Must match the Server's mode; see build_codec/ENCRYPTION_MODES.
        self.codec = build_codec(encryption)
        self.encryption = self.codec.mode
        self.encryption_service = self.codec.encryption_service

        self.host = host
        self.port = port

        self.on_receive = on_receive
        self.receive_queue = queue.Queue()
        self.areceive_queue = asyncio.Queue()

        self.send_conn: socket.socket | None = None
        self.receive_conn: socket.socket | None = None

        self.receiving = False
        self.receiving_thread: threading.Thread | None = None
        self._receiving_thread: threading.Thread | None = None

        self.receiving_task: threading.Thread | None = None
        self._receiving_task: asyncio.Task | None = None

        # One request occupies the send socket until its ack comes back, so
        # concurrent send()/asend() calls have to take turns.
        self._send_lock = threading.Lock()
        self._asend_lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def encrypt(self, data: bytes) -> bytes:
        return self.codec.encode(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.codec.decode(data)

    def send(self, method: str, data: bytes) -> str:
        # self.ping()
        request_id = str(uuid.uuid4())
        with self._send_lock:
            send(self.send_conn, self.encrypt(SPLIT_TOKEN.join([method.encode(), request_id.encode(), data])))
            receive(self.send_conn)
        return request_id
    
    def send_obj(self, method: str, data: dict | list | int | float | bool | str | None) -> str:
        return self.send(method, json.dumps(data).encode())

    def __receive_thread(self) -> None:
        while (data := self.receive_queue.get()) is not None:
            try:
                if not data:
                    continue

                # maxsplit=1: the payload is the last field and may itself
                # contain SPLIT_TOKEN.
                request_id, data = self.decrypt(data).split(SPLIT_TOKEN, 1)

                if data == b'__close__':
                    break

                run_maybe_async(self.on_receive, Message(request_id.decode(), data))
            except Exception as e:
                print(f'Error handling received data: {e}')
                traceback.print_exc()
                break
    
    def _receive_thread(self) -> None:
        while self.receiving:
            try:
                data = receive(self.receive_conn)
            except (ConnectionClosed, OSError):
                # Peer hung up. Stop, rather than spinning on a dead socket.
                break
            except Exception as e:
                print(f'Error receiving data: {e}')
                traceback.print_exc()
                break

            if data:
                self.receive_queue.put(data)
        self.receive_queue.put(None)

    @staticmethod
    def is_socket_healthy(sock):
        """Checks connection status by attempting a zero-byte send."""
        try:
            # Returns 0 on success, which indicates the connection is still up.
            sock.send(b'')
            return True
        except socket.error:
            # Catches exceptions like ConnectionResetError or BrokenPipeError.
            return False
        except Exception:
            # Catches other unexpected errors
            return False
    
    def ping(self):
        if not self.is_socket_healthy(self.send_conn) or not self.is_socket_healthy(self.receive_conn):
            raise ConnectionError('Connection lost')
    
    def open(self) -> None:
        # Send the client ID to the server
        # self.send(self.client_id.encode())

        self.receive_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.receive_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.receive_conn.connect((self.host, self.port))

        send(self.receive_conn, self.encrypt(SPLIT_TOKEN.join([b'receive', self.client_id.encode()])))
        assert b'ok' == self.decrypt(receive(self.receive_conn))

        # Start the receive thread
        self.receiving = True
        self.receiving_thread = threading.Thread(target=self._receive_thread, daemon=True)
        self.receiving_thread.start()
        self._receiving_thread = threading.Thread(target=self.__receive_thread, daemon=True)
        self._receiving_thread.start()

        self.send_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.send_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.send_conn.connect((self.host, self.port))

        send(self.send_conn, self.encrypt(SPLIT_TOKEN.join([b'send', self.client_id.encode()])))
        assert b'ok' == self.decrypt(receive(self.send_conn))

    def close(self) -> None:
        try:
            self.send('close', b'closing')
            assert self.decrypt(self.server_receive(self.send_conn)) == b'__close__'
        finally:
            self.receiving = False

            # The reader thread is parked in a blocking recv(); shut the socket
            # down so it returns instead of the join() below hanging on it.
            shutdown_socket(self.receive_conn)

            for thread in (self.receiving_thread, self._receiving_thread):
                if thread:
                    thread.join(timeout=SHUTDOWN_TIMEOUT)
            self.receiving_thread = None
            self._receiving_thread = None

            if self.send_conn:
                self.send_conn.close()
            if self.receive_conn:
                self.receive_conn.close()
    
    def server_receive(self, s):
        return receive(s)

    async def __aenter__(self):
        await self.aopen()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    async def aencrypt(self, data: bytes) -> bytes:
        # Only the bz2 in 'secure' is slow enough that handing it to a thread beats
        # running it inline; for the other modes the hop is pure overhead.
        if not self.codec.offload:
            return self.codec.encode(data)
        return await asyncio.to_thread(self.encrypt, data)

    async def adecrypt(self, data: bytes) -> bytes:
        if not self.codec.offload:
            return self.codec.decode(data)
        return await asyncio.to_thread(self.decrypt, data)

    async def asend(self, method: str, data: bytes) -> str:
        # await self.aping()
        request_id = str(uuid.uuid4())
        async with self._asend_lock:
            await async_send(self.send_conn, await self.aencrypt(SPLIT_TOKEN.join([method.encode(), request_id.encode(), data])))
            await async_receive(self.send_conn)
        return request_id
    
    async def asend_obj(self, method: str, data: dict | list | int | float | bool | str | None) -> str:
        return await self.asend(method, json.dumps(data).encode())

    async def __areceive_thread(self) -> None:
        while (data := await self.areceive_queue.get()) is not None:
            try:
                if not data:
                    continue

                request_id, data = (await self.adecrypt(data)).split(SPLIT_TOKEN, 1)

                if data == b'__close__':
                    break

                await run_as_async(self.on_receive, Message(request_id.decode(), data))
            except Exception as e:
                print(f'Error handling received data: {e}')
                traceback.print_exc()
                break
    
    def _areceive_thread(self) -> None:
        # Runs in a worker thread; asyncio.Queue is not thread safe, so every
        # hand-off has to go through the loop.
        def put(item):
            try:
                self._loop.call_soon_threadsafe(self.areceive_queue.put_nowait, item)
            except RuntimeError:
                pass  # loop already closed

        while self.receiving:
            try:
                data = receive(self.receive_conn)
            except (ConnectionClosed, OSError):
                break
            except Exception as e:
                print(f'Error receiving data: {e}')
                traceback.print_exc()
                break

            if data:
                put(data)
        put(None)

    @staticmethod
    async def ais_socket_healthy(sock):
        """Checks connection status by attempting a zero-byte send."""
        try:
            # Returns 0 on success, which indicates the connection is still up.
            loop = asyncio.get_running_loop()
            await loop.sock_sendall(sock, b'')
            # sock.send(b'')
            return True
        except socket.error:
            # Catches exceptions like ConnectionResetError or BrokenPipeError.
            return False
        except Exception:
            # Catches other unexpected errors
            return False
    
    async def aping(self):
        if not (await self.ais_socket_healthy(self.send_conn)) or not (await asyncio.to_thread(self.is_socket_healthy, self.receive_conn)):
            raise ConnectionError('Connection lost')
    
    async def aopen(self) -> None:
        loop = asyncio.get_running_loop()
        self._loop = loop

        def receive_socket_setup():
            self.receive_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # self.receive_conn.setblocking(False)
            self.receive_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # await loop.sock_connect(self.receive_conn, (self.host, self.port))
            self.receive_conn.connect((self.host, self.port))

            # await async_send(self.receive_conn, await self.aencrypt(SPLIT_TOKEN.join([b'receive', self.client_id.encode()])))
            # assert b'ok' == await self.adecrypt(await async_receive(self.receive_conn))
            send(self.receive_conn, self.encrypt(SPLIT_TOKEN.join([b'receive', self.client_id.encode()])))
            assert b'ok' == self.decrypt(receive(self.receive_conn))
        
        await asyncio.to_thread(receive_socket_setup)

        # Start the receive thread
        self.receiving = True
        self.receiving_task = threading.Thread(target=self._areceive_thread, daemon=True)  # asyncio.create_task(self._areceive_thread())
        self.receiving_task.start()
        self._receiving_task = asyncio.create_task(self.__areceive_thread())
        # self._receiving_task.start()

        self.send_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.send_conn.setblocking(False)
        self.send_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        await loop.sock_connect(self.send_conn, (self.host, self.port))
        # self.send_conn.connect((self.host, self.port))

        await async_send(self.send_conn, await self.aencrypt(SPLIT_TOKEN.join([b'send', self.client_id.encode()])))
        assert b'ok' == await self.adecrypt(await async_receive(self.send_conn))

    async def aclose(self) -> None:
        try:
            await self.asend('close', b'closing')
            assert (await self.adecrypt(await self.aserver_receive(self.send_conn))) == b'__close__'
        finally:
            self.receiving = False
            shutdown_socket(self.receive_conn)

            if self.receiving_task:
                # join() in a worker thread; blocking it here would stop the
                # loop that the reader thread needs in order to finish.
                await asyncio.to_thread(self.receiving_task.join, SHUTDOWN_TIMEOUT)
                self.receiving_task = None

            if self._receiving_task:
                try:
                    await asyncio.wait_for(self._receiving_task, timeout=SHUTDOWN_TIMEOUT)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    self._receiving_task.cancel()
                self._receiving_task = None

            if self.send_conn:
                self.send_conn.close()
            if self.receive_conn:
                self.receive_conn.close()
    
    async def aserver_receive(self, s):
        return await async_receive(s)


async def run_as_async(func, *args, **kwargs) -> Any:
    if inspect.iscoroutinefunction(func):
        return await func(*args, **kwargs)
    return await asyncio.to_thread(func, *args, **kwargs)


def run_maybe_async(func, *args, **kwargs) -> Any:
    """Call `func` from synchronous code, awaiting it if it is a coroutine function.

    Without this a user handler defined with `async def` would only ever produce a
    coroutine object that nobody awaits, so its body would silently never run.
    """
    if inspect.iscoroutinefunction(func):
        return asyncio.run(func(*args, **kwargs))
    return func(*args, **kwargs)


def shutdown_socket(sock: socket.socket | None) -> None:
    """Unblock any thread parked in recv() on `sock`; closing alone may not."""
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


@dataclass
class ServerRequest:
    client_id: str
    request_id: str
    method: str
    data: bytes
    send_data: Callable[[bytes], None]

    def send(self, data: str) -> None:
        self.send_data(data.encode())


@dataclass
class OnOpenInfo:
    client_id: str


@dataclass
class OnCloseInfo:
    client_id: str


@dataclass
class OnFinallyInfo:
    client_id: str | None


class Server:
    def __init__(
            self, 
            host: str, 
            port: int, 
            handler: Callable[[ServerRequest], None | Awaitable[None]],
            on_close: Callable[[OnCloseInfo], None | Awaitable[None]] = None,
            on_close_receive: Callable[[OnCloseInfo], None | Awaitable[None]] = None,

            on_open: Callable[[OnOpenInfo], None | Awaitable[None]] = None,
            on_open_receive: Callable[[OnOpenInfo], None | Awaitable[None]] = None,

            on_finally: Callable[[OnFinallyInfo], None | Awaitable[None]] = None,

            encryption: str | bool | None = None,
        ):
        self.host = host
        self.port = port
        self.handler = handler
        self.on_close: Callable[[OnCloseInfo], None | Awaitable[None]] = on_close
        self.on_close_receive: Callable[[OnCloseInfo], None | Awaitable[None]] = on_close_receive
        self.on_open: Callable[[OnOpenInfo], None | Awaitable[None]] = on_open
        self.on_open_receive: Callable[[OnOpenInfo], None | Awaitable[None]] = on_open_receive
        self.on_finally: Callable[[OnFinallyInfo], None | Awaitable[None]] = on_finally

        self.client_queue: dict[str, queue.Queue | asyncio.Queue] = {}
        self.client_send_socket: dict[str, socket.socket] = {}

        # Must match every Client's mode; see build_codec/ENCRYPTION_MODES.
        self.codec = build_codec(encryption)
        self.encryption = self.codec.mode
        self.encryption_service = self.codec.encryption_service

    def encrypt(self, data: bytes) -> bytes:
        return self.codec.encode(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.codec.decode(data)

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            attempts = 5
            for attempt in range(1, attempts + 1):
                try:
                    server.bind((self.host, self.port))
                    break
                except OSError:
                    print(f"Port {self.port} is already in use. Retrying...")
                    time.sleep(5 * attempt)
                    if attempt == attempts:
                        raise
            server.listen()
            print(f"Server listening on {self.host}:{self.port}")

            while True:
                client_socket, addr = server.accept()
                print(f"Connection from {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True)
                client_thread.start()
        finally:
            # shutdown() on a listening socket raises ENOTCONN and would mask
            # whatever exception actually broke the accept loop.
            server.close()
    
    def server_receive(self, s):
        while not (data := receive(s)):
            pass
        return data
    
    def handle_requests(self, client_id: str, s, q: queue.Queue, request_q: queue.Queue, loop=None):
        # This always runs in a worker thread. When `loop` is set the queues are
        # asyncio queues owned by that loop, and asyncio queues are not thread
        # safe, so every put has to be routed back through the loop.
        def put(target_q, item):
            if loop:
                loop.call_soon_threadsafe(target_q.put_nowait, item)
            else:
                target_q.put_nowait(item)

        def get_send_data_func(req_id: bytes):
            def send_data(data: bytes) -> None:
                put(q, SPLIT_TOKEN.join([req_id, data]))
            return send_data

        try:
            # maxsplit=2: the payload is the last field and may contain SPLIT_TOKEN.
            method, request_id, data = self.decrypt(self.server_receive(s)).split(SPLIT_TOKEN, 2)
            send(s, b'ok')

            while method != b'close':
                put(
                    request_q,
                    ServerRequest(
                        client_id,
                        request_id.decode(),
                        method.decode(),
                        data,
                        get_send_data_func(request_id)
                    )
                )
                method, request_id, data = self.decrypt(self.server_receive(s)).split(SPLIT_TOKEN, 2)
                send(s, b'ok')
        except (ConnectionClosed, OSError):
            pass  # client went away; fall through and stop the handler loop
        except Exception as e:
            print(f'Error handling requests from {client_id}: {e}')
            traceback.print_exc()
        finally:
            put(request_q, None)
        
        
    def handle_client(self, s):
        client_id = None
        try:
            with s:
                client_type, client_id = self.decrypt(receive(s)).split(SPLIT_TOKEN, 1)
                client_id = client_id.decode()

                if client_type == b'send':
                    try:
                        request_q: queue.Queue = queue.Queue()
                        
                        q: queue.Queue = queue.Queue()
                        self.client_queue[client_id] = q
                        self.client_send_socket[client_id] = s

                        if callable(self.on_open):
                            run_maybe_async(self.on_open, OnOpenInfo(client_id))

                        send(s, self.encrypt(b'ok'))

                        # method, request_id, data = self.decrypt(self.server_receive(s)).split(SPLIT_TOKEN)
                        # while method != b'close':
                        #     def send_data(data: bytes) -> None:
                        #         q.put(SPLIT_TOKEN.join([request_id, data]))
                        #     self.handler(ServerRequest(method.decode(), data, send_data))
                        #     method, request_id, data = self.decrypt(self.server_receive(s)).split(SPLIT_TOKEN)

                        t = threading.Thread(target=self.handle_requests, args=(client_id, s, q, request_q), daemon=True)
                        t.start()

                        while (request := request_q.get()) is not None:
                            request: ServerRequest
                            # print('handling', request)
                            run_maybe_async(self.handler, request)

                        q.put(b'close')
                        # Wait for the receive side to drain, but do not park
                        # this thread forever if that client never shows up.
                        deadline = time.time() + CLIENT_TEARDOWN_TIMEOUT
                        while client_id in self.client_send_socket and time.time() < deadline:
                            time.sleep(0.1)
                    finally:
                        self.client_queue.pop(client_id, None)
                        self.client_send_socket.pop(client_id, None)
                        if callable(self.on_close):
                            try:
                                run_maybe_async(self.on_close, OnCloseInfo(client_id))
                            except Exception as e:
                                print(f'Error in on_close: {e}')
                                traceback.print_exc()
                elif client_type == b'receive':
                    try:
                        if callable(self.on_open_receive):
                            run_maybe_async(self.on_open_receive, OnOpenInfo(client_id))
                        send(s, self.encrypt(b'ok'))

                        t = time.time()
                        while client_id not in self.client_queue:
                            time.sleep(0.1)
                            if time.time() - t > 60:
                                raise ValueError('Timeout waiting for client queue')
                        
                        # No annotation: `q` is already bound in the send branch
                        # above, and Cython rejects a second declaration.
                        q = self.client_queue[client_id]

                        while (data := q.get()) != b'close':
                            if data:
                                send(s, self.encrypt(data))
                                
                        send(s, self.encrypt(SPLIT_TOKEN.join([b'empty-id', b'__close__'])))
                    finally:
                        # Unregister even if the client vanished mid-write,
                        # otherwise these dicts grow for every dropped client.
                        self.client_queue.pop(client_id, None)
                        send_socket = self.client_send_socket.pop(client_id, None)
                        if send_socket is not None:
                            try:
                                send(send_socket, self.encrypt(b'__close__'))
                            except OSError:
                                pass  # client already gone

                        if callable(self.on_close_receive):
                            try:
                                run_maybe_async(self.on_close_receive, OnCloseInfo(client_id))
                            except Exception as e:
                                print(f'Error in on_close_receive: {e}')
                                traceback.print_exc()
                # method, data = receive(s).split(SPLIT_TOKEN)
        except (ConnectionClosed, OSError) as e:
            # A client dropping its connection is routine, not a crash.
            print(f'Client {client_id} disconnected: {e}')
        finally:
            if callable(self.on_finally):
                try:
                    run_maybe_async(self.on_finally, OnFinallyInfo(client_id))
                except Exception as e:
                    print(f'Error in on_finally: {e}')
                    traceback.print_exc()

    async def aencrypt(self, data: bytes) -> bytes:
        # See Client.aencrypt: the thread hop only pays for itself under 'secure'.
        if not self.codec.offload:
            return self.codec.encode(data)
        return await asyncio.to_thread(self.encrypt, data)

    async def adecrypt(self, data: bytes) -> bytes:
        if not self.codec.offload:
            return self.codec.decode(data)
        return await asyncio.to_thread(self.decrypt, data)

    async def astart(self):
        loop = asyncio.get_running_loop()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setblocking(False)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # await loop.sock_accept(self.send_conn, (self.host, self.port))

        try:
            attempts = 5
            for attempt in range(1, attempts + 1):
                try:
                    server.bind((self.host, self.port))
                    break
                except OSError:
                    print(f"Port {self.port} is already in use. Retrying...")
                    await asyncio.sleep(5 * attempt)
                    if attempt == attempts:
                        raise
            server.listen()
            print(f"Server listening on {self.host}:{self.port}")

            while True:
                client_socket, addr = await loop.sock_accept(server)  # server.accept()
                print(f"Connection from {addr}")
                # client_thread = threading.Thread(target=self.ahandle_client, args=(client_socket,), daemon=True)
                # client_thread.start()
                client_socket.setblocking(False)
                asyncio.create_task(self.ahandle_client(client_socket))
        finally:
            server.close()
    
    async def aserver_receive(self, s):
        while not (data := await async_receive(s)):
            pass
        return data
    
    async def ahandle_requests(self, client_id: str, s, q: asyncio.Queue, request_q: asyncio.Queue):
        method, request_id, data = (await self.adecrypt(await self.aserver_receive(s))).split(SPLIT_TOKEN, 2)
        await async_send(s, b'ok')

        while method != b'close':
            # async def send_data(data: bytes) -> None:
            #     await q.put(SPLIT_TOKEN.join([request_id, data]))
            def get_send_data_func(req_id: bytes):
                def send_data(data: bytes) -> None:
                    q.put_nowait(SPLIT_TOKEN.join([req_id, data]))
                return send_data
                
            await request_q.put(ServerRequest(client_id, request_id.decode(), method.decode(), data, get_send_data_func(request_id)))
            # self.handler(ServerRequest(method.decode(), data, send_data))
            method, request_id, data = (await self.adecrypt(await self.aserver_receive(s))).split(SPLIT_TOKEN, 2)
            await async_send(s, b'ok')
        
        await request_q.put(None)
        
        
    async def ahandle_client(self, s: socket.socket):
        client_id = None
        try:
            with s:
                client_type, client_id = (await self.adecrypt(await async_receive(s))).split(SPLIT_TOKEN, 1)
                client_id = client_id.decode()

                if client_type == b'send':
                    try:
                        request_q: asyncio.Queue = asyncio.Queue()
                    
                        q: asyncio.Queue = asyncio.Queue()
                        self.client_queue[client_id] = q
                        self.client_send_socket[client_id] = s

                        if callable(self.on_open):
                            await run_as_async(self.on_open, OnOpenInfo(client_id))

                        await async_send(s, self.encrypt(b'ok'))

                        s.setblocking(True)
                        t = threading.Thread(target=self.handle_requests, args=(client_id, s, q, request_q, asyncio.get_running_loop()), daemon=True)
                        t.start()
                        # asyncio.create_task(self.ahandle_requests(s, q, request_q))

                        while (request := await request_q.get()) is not None:
                            request: ServerRequest
                            await run_as_async(self.handler, request)
                    
                        await q.put(b'close')
                        deadline = time.time() + CLIENT_TEARDOWN_TIMEOUT
                        while client_id in self.client_send_socket and time.time() < deadline:
                            await asyncio.sleep(0.1)
                    finally:
                        self.client_queue.pop(client_id, None)
                        self.client_send_socket.pop(client_id, None)
                        if callable(self.on_close):
                            try:
                                await run_as_async(self.on_close, OnCloseInfo(client_id))
                            except Exception as e:
                                print(f'Error in on_close: {e}')
                                traceback.print_exc()
                elif client_type == b'receive':
                    try:
                        if callable(self.on_open_receive):
                            await run_as_async(self.on_open_receive, OnOpenInfo(client_id))

                        await async_send(s, await self.aencrypt(b'ok'))

                        t = time.time()
                        while client_id not in self.client_queue:
                            await asyncio.sleep(0.1)
                            if time.time() - t > 60:
                                raise ValueError('Timeout waiting for client queue')
                    
                        q = self.client_queue[client_id]

                        while (data := await q.get()) != b'close':
                            if data:
                                await async_send(s, await self.aencrypt(data))

                        await async_send(s, await self.aencrypt(SPLIT_TOKEN.join([b'empty-id', b'__close__'])))
                    finally:
                        self.client_queue.pop(client_id, None)
                        send_socket = self.client_send_socket.pop(client_id, None)
                        if send_socket is not None:
                            # The send socket was handed to handle_requests in
                            # blocking mode; flipping it back here would race that
                            # thread, so write to it the same blocking way.
                            try:
                                await asyncio.to_thread(send, send_socket, self.encrypt(b'__close__'))
                            except OSError:
                                pass  # client already gone

                        if callable(self.on_close_receive):
                            try:
                                await run_as_async(self.on_close_receive, OnCloseInfo(client_id))
                            except Exception as e:
                                print(f'Error in on_close_receive: {e}')
                                traceback.print_exc()
                # method, data = receive(s).split(SPLIT_TOKEN)
        except (ConnectionClosed, OSError) as e:
            print(f'Client {client_id} disconnected: {e}')
        finally:
            if callable(self.on_finally):
                try:
                    await run_as_async(self.on_finally, OnFinallyInfo(client_id))
                except Exception as e:
                    print(f'Error in on_finally: {e}')
                    traceback.print_exc()


def server_handler_example(request: ServerRequest) -> None:
    if request.method == 'echo':
        request.send_data(request.data)

# # async not supported at this time
# async def aserver_handler_example(request: ServerRequest) -> None:
#     if request.method == 'echo':
#         request.send_data(request.data)


BiServer = Server
BiClient = Client
BiMessage = Message
BiServerRequest = ServerRequest







