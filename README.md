# `bisocket`: Simple, Secure, Bidirectional Python Sockets

[![PyPI](https://img.shields.io/pypi/v/bisocket.svg)](https://pypi.org/project/bisocket/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`bisocket` is a high-level Python library that simplifies bidirectional (two-way) communication over sockets. It provides a robust framework for building client-server applications that require sending and receiving data simultaneously without blocking.

It comes with built-in **AES-GCM end-to-end encryption** and **bz2 compression**, ensuring your data is secure and transmitted efficiently. The library offers both synchronous (threading-based) and asynchronous (`asyncio`) APIs, making it versatile for various application architectures.

-----

## ✨ Features

  - **True Bidirectional Communication**: Uses separate sockets for sending and receiving, enabling non-blocking, full-duplex communication.
  - **End-to-End Encryption**: Automatic AES-GCM encryption for all messages ensures data privacy and integrity.
  - **Selectable Encryption Modes**: `secure`, `faster` or `off` per `Client`/`Server`, so a service on a trusted private network can trade protection for throughput.
  - **Sync & Async Support**: Provides both a standard threading API and a modern `asyncio` API.
  - **Simple Handler-Based API**: Use a clean handler function on the server and an `on_receive` callback on the client to process messages.
  - **Unique Client Identification**: Manages clients using unique UUIDs, making it easy to track connections.
  - **Connection Lifecycle Hooks**: Optional `on_open`, `on_close` and `on_finally` callbacks on the server, each told which of the client's two sockets it is for.
  - **Handler Failures Stay Local**: An exception in one request's handler is reported to that client and does not disturb the connection or any other request.

-----

## ⚙️ Installation

Install `bisocket` directly from PyPI:

```bash
pip install bisocket
```

The only runtime dependency is the `cryptography` library for encryption.

If Cython and a C compiler are available at install time, a compiled build of the
library is used automatically. If they are not, the install still succeeds and the
identical pure-Python implementation is used instead. Both are built from the same
source, so behaviour does not differ. To see which one you got:

```bash
python -c "import bisocket; print(bisocket.main.__file__)"
```

-----

## 🚀 Quick Start

Here's a simple echo client and server to get you started.

### 1\. Set the Encryption Key

For security, `bisocket` requires an encryption key. Set it as an environment variable. If it's not set, the library prints a warning and falls back to a default, **insecure** key suitable only for testing.

```bash
export CRYPTO_KEY='your-super-secret-and-long-encryption-key'
```

### 2\. Synchronous Example

#### Server (`server.py`)

```python
from bisocket import Server, ServerRequest

# Define a handler to process incoming requests.
def handler(request: ServerRequest):
    print(f"Received method '{request.method}' with data: {request.data.decode()}")

    if request.method == 'echo':
        # Send the received data back to the client.
        request.send_data(request.data)
    elif request.method == 'ping':
        request.send_data(b'pong')

# Create and start the server.
if __name__ == "__main__":
    server = Server(host='127.0.0.1', port=65432, handler=handler)
    print("Starting synchronous server on port 65432...")
    server.start()
```

#### Client (`client.py`)

```python
import time
from bisocket import Client, Message

# Define a callback to handle messages from the server.
def on_receive(msg: Message):
    print(f"Received response for request ID {msg.request_id}: {msg.data.decode()}")

# Use the Client as a context manager for clean connection handling.
with Client(host='127.0.0.1', port=65432, on_receive=on_receive) as client:
    print("Client connected.")

    # Send an 'echo' request.
    request_id_1 = client.send('echo', b'Hello, World!')
    print(f"Sent 'echo' request with ID: {request_id_1}")

    time.sleep(1) # Wait for the response.

    # Send a 'ping' request.
    request_id_2 = client.send('ping', b'')
    print(f"Sent 'ping' request with ID: {request_id_2}")

    time.sleep(2) # Give time for messages to be processed before exiting.

print("Client disconnected.")
```

-----

### 3\. Asynchronous Example

Use `Server.astart()` and the client's `aopen()` / `asend()` / `aclose()` (or `async with`)
for the asyncio API. An `async def` handler works with either server, but the
synchronous `Server.start()` has to spin up an event loop per call, so prefer
`astart()` when your handler is a coroutine.

#### Async Server (`async_server.py`)

```python
import asyncio
from bisocket import Server, ServerRequest

# Define an async handler for non-blocking operations.
async def ahandler(request: ServerRequest):
    print(f"Received method '{request.method}' with data: {request.data.decode()}")

    if request.method == 'echo':
        await asyncio.sleep(0.5) # Simulate I/O-bound work.
        request.send_data(request.data)

# Create and run the async server.
async def main():
    server = Server(host='127.0.0.1', port=65432, handler=ahandler)
    print("Starting asynchronous server on port 65432...")
    await server.astart()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server shutting down.")
```

#### Async Client (`async_client.py`)

```python
import asyncio
from bisocket import Client, Message

# Define an async callback to process server messages.
async def aon_receive(msg: Message):
    print(f"Received response for request ID {msg.request_id}: {msg.data.decode()}")

async def main():
    # Use the async context manager for the client.
    async with Client(host='127.0.0.1', port=65432, on_receive=aon_receive) as client:
        print("Async client connected.")

        # Send multiple requests concurrently.
        tasks = [
            client.asend('echo', b'First async message'),
            client.asend('echo', b'Second async message')
        ]
        request_ids = await asyncio.gather(*tasks)
        print(f"Sent requests with IDs: {request_ids}")

        await asyncio.sleep(2) # Keep client running to receive responses.

if __name__ == "__main__":
    asyncio.run(main())
```

-----

## 📚 API Reference

### `Client(host, port, on_receive, encryption=None, require_key=None)`

`on_receive` is called with a `Message` for every message pushed by the server. It
may be a normal function or an `async def` coroutine function.

`encryption` selects the wire format -- see [Encryption Modes](#-encryption-modes).
`require_key` is described under [Requiring a key](#requiring-a-key).

| Method | Description |
| --- | --- |
| `open()` / `close()` | Connect and disconnect. Also available as a `with` block. |
| `aopen()` / `aclose()` | Async equivalents. Also available as an `async with` block. |
| `send(method, data) -> str` | Send `bytes` under a method name; returns the request ID. |
| `send_obj(method, obj) -> str` | Same, but JSON-encodes `obj` first. |
| `asend(...)` / `asend_obj(...)` | Async equivalents. |
| `ping()` / `aping()` | Raise `ConnectionError` if either socket has dropped. |

`send()` and `asend()` are safe to call concurrently from multiple threads or tasks;
each call holds the send socket until its acknowledgement returns.

### `Message`

| Attribute / Method | Description |
| --- | --- |
| `request_id: str` | ID of the request this message answers. |
| `data: bytes` | Raw payload. |
| `get_str() -> str` | Payload decoded as UTF-8. |
| `get_obj()` | Payload parsed as JSON. |
| `is_error: bool` | True if the server's handler raised on this request. |
| `error` | `HandlerErrorInfo` for a failure, else `None`. |
| `raise_for_error()` | Raise `HandlerError` if this is a failure; else return `self`. |

See [When a handler raises](#when-a-handler-raises).

### `Server(host, port, handler, ...)`

| Argument | Called when |
| --- | --- |
| `handler` | A request arrives. Receives a `ServerRequest`. |
| `on_open` | A client's send socket connects. Receives `OnOpenInfo`. |
| `on_open_receive` | A client's receive socket connects. Receives `OnOpenInfo`. |
| `on_close` | A client's send socket closes. Receives `OnCloseInfo`. |
| `on_close_receive` | A client's receive socket closes. Receives `OnCloseInfo`. |
| `on_finally` | Any client connection ends, for any reason. Receives `OnFinallyInfo`. |

`Server` also takes:

| Argument | Default | Meaning |
| --- | --- | --- |
| `encryption` | `None` | Wire format -- see [Encryption Modes](#-encryption-modes). |
| `require_key` | `None` | Fail at construction if `CRYPTO_KEY` is unset -- see [Requiring a key](#requiring-a-key). |
| `send_error_traceback` | `False` | Include the server-side traceback in error replies -- see [When a handler raises](#when-a-handler-raises). |

Every callback, and `handler` itself, may be a normal function or an `async def`
coroutine function.

| Method | Description |
| --- | --- |
| `start()` | Run the threaded server. Blocks forever. |
| `astart()` | Run the asyncio server. Blocks forever. |

-----

### Which callback fires for which socket

This is the least obvious part of the API, so it is worth stating exactly.

Each client holds **two** connections under one `client_id` (see
[How It Works](#-how-it-works)). `on_open`/`on_close` are send-socket events and
`on_open_receive`/`on_close_receive` are receive-socket events, but **`on_finally`
is per connection**, so it fires **twice** per client.

Every payload carries a `connection_type` saying which socket it is about:

| Payload | Fields |
| --- | --- |
| `OnOpenInfo` | `client_id: str`, `connection_type: str \| None` |
| `OnCloseInfo` | `client_id: str`, `connection_type: str \| None` |
| `OnFinallyInfo` | `client_id: str \| None`, `connection_type: str \| None` |

`connection_type` is `'send'`, `'receive'`, or `None` when the handshake failed
before the socket said which it was — in which case `client_id` is `None` too.
The constants `bisocket.CONNECTION_SEND` and `bisocket.CONNECTION_RECEIVE` hold
those two strings.

For one client that connects, sends a request and disconnects, the order is:

| # | Callback | `connection_type` |
| --- | --- | --- |
| 1 | `on_open_receive` | `'receive'` |
| 2 | `on_open` | `'send'` |
| 3 | `on_close_receive` | `'receive'` |
| 4 | **`on_finally`** | **`'receive'`** |
| 5 | `on_close` | `'send'` |
| 6 | **`on_finally`** | **`'send'`** |

Note steps 4 and 5: the **receive socket's `on_finally` arrives before
`on_close`**. This matters if you allocate per-client resources in `on_open` and
free them in `on_finally` — the first `on_finally` fires while the client is still
live, so freeing there gives away a still-running client's state. Filter on
`connection_type` instead:

```python
from bisocket import Server, CONNECTION_SEND

def on_finally(info):
    # Fires exactly once per client, after on_close, when the client is really gone.
    if info.connection_type == CONNECTION_SEND:
        release_resources_for(info.client_id)
```

`connection_type` is a field with a default of `None`, so existing callbacks — and
any code constructing these payloads positionally — keep working unchanged.

### `ServerRequest`

| Attribute / Method | Description |
| --- | --- |
| `client_id: str` | UUID of the sending client. |
| `request_id: str` | UUID of this request. |
| `method: str` | Method name the client sent. |
| `data: bytes` | Raw payload. |
| `send_data(data: bytes)` | Queue a `bytes` response back to that client. |
| `send(data: str)` | Same, for a `str`. |
| `send_error(exc)` | Queue a response the client will see as a failure. |

A handler may call `send_data()` any number of times, including zero. Responses are
pushed over the client's receive socket, so they are not tied to a request/response
turn.

### When a handler raises

A `handler` that raises does not disturb the connection. The failure is logged
server-side with its traceback, the loop moves on to the next request, and the
client gets a reply on that `request_id` marked as an error — so a caller awaiting
that request is never left waiting forever:

```python
from bisocket import Client, HandlerError

def on_receive(message):
    if message.is_error:
        print(f'request {message.request_id} failed: {message.error}')
        # -> request 8f3c... failed: ValueError handling 'resize': bad dimensions
        return
    handle(message.get_obj())
```

`message.error` is a `HandlerErrorInfo` with `type`, `message`, `method` and
`traceback`. `message.raise_for_error()` re-raises it locally as a `HandlerError`
if you would rather handle it as an exception.

The traceback is **not** sent by default, since it names server-side files and
code. Pass `Server(..., send_error_traceback=True)` on a server whose clients are
trusted to see it.

Error replies ride inside the existing payload field, behind a marker byte string,
so a client that never checks `is_error` still receives an ordinary, well-formed
`Message` on the right `request_id` rather than failing to parse anything.

A handler may still return without sending anything; only a handler that *raises*
produces an error reply.

-----

### Aliases

`BiClient`, `BiServer`, `BiMessage` and `BiServerRequest` are aliases for `Client`,
`Server`, `Message` and `ServerRequest`.

### Exceptions

| Exception | Raised when |
| --- | --- |
| `ConnectionClosed` | The peer went away mid-frame. Subclasses `ConnectionError`. |
| `EncryptionMismatch` | A frame could not be read under this peer's mode. Subclasses `ValueError`. |
| `MissingCryptoKey` | `require_key` is on and `CRYPTO_KEY` is unset. Subclasses `RuntimeError`. |
| `HandlerError` | Raised by `Message.raise_for_error()`. Carries `.info`. |

-----

## 🧠 How It Works

Traditional socket programming can be tricky when you need to send and receive data at the same time, often leading to blocking calls or complex multiplexing.

`bisocket` simplifies this by establishing **two separate socket connections** for each client:

1.  **Send Socket**: The client uses this connection exclusively to send data *to* the server.
2.  **Receive Socket**: The client uses this connection exclusively to receive data *from* the server.

This architecture allows the client and server to communicate in full-duplex mode without one operation blocking the other. The library manages these connections, message framing, encryption, and compression internally, so you can focus on your application logic.

  - **On the Client**: The `Client` runs a background thread (or `asyncio` task) to listen for incoming messages on the receive socket. These messages are passed to your `on_receive` callback.
  - **On the Server**: The `Server` manages a pool of client connections. It receives a request from a client's "send" socket, processes it in your handler, and then queues the response to be sent back via that same client's "receive" socket.

Messages are delimited on the wire by a byte token. Your own payloads may contain
any bytes, delimiters included: `secure` and `faster` frame ciphertext, and `off`
escapes the rare payload that contains the delimiter (see below).

-----

## ⚡ Encryption Modes

Encryption is on by default. Pass `encryption=` to a `Client` or a `Server`, or set
`BISOCKET_ENCRYPTION` for the whole process:

```python
server = bisocket.Server('0.0.0.0', 9000, handler, encryption='faster')
client = bisocket.Client('10.0.0.5', 9000, on_receive, encryption='faster')
```

```bash
export BISOCKET_ENCRYPTION=faster   # process-wide default
```

An explicit `encryption=` argument always wins over the environment variable.

| Mode | Encrypted | Per-frame work | Use it when |
| --- | --- | --- | --- |
| `'secure'` *(default)* | AES-256-GCM | Encrypt, then `bz2` level 9 | You need the 0.0.8 wire format, e.g. while a fleet is mid-upgrade. |
| `'faster'` | AES-256-GCM | Encrypt only | **Almost always.** Same protection as `secure`, dramatically cheaper. |
| `'off'` | **No** | None | Throughput matters more than confidentiality *and* the network is fully trusted. |

`True` / `False` are accepted as shorthand for `'secure'` / `'off'`.

### Which mode should I use?

**Use `'faster'`.** The `secure` pipeline compresses *after* encrypting, so its
`bz2` pass is compressing ciphertext -- which is incompressible. It costs a great
deal of CPU per frame and does not shrink anything; on a 1 MB payload it actually
*adds* about 6 KB. Round-trip encode+decode of one frame, measured locally:

| Payload | `'secure'` | `'faster'` | `'off'` |
| --- | --- | --- | --- |
| 200 B | 0.084 ms | 0.003 ms | 0.0004 ms |
| 20 KB | 4.3 ms | 0.015 ms | 0.015 ms |
| 1 MB | 220 ms | 0.7 ms | 0.9 ms |

So `'faster'` is roughly **300x** cheaper than the default while sending slightly
fewer bytes, and it gives up no confidentiality whatsoever. AES-GCM is
hardware-accelerated and costs well under a millisecond per megabyte, which is why
`'off'` buys almost nothing beyond `'faster'` -- and loses to it on large payloads,
since it has to copy the buffer that AES-GCM would have transformed in place.

Reach for `'off'` only for very small, very high-rate frames on a trusted network,
where avoiding nonce generation is measurable.

### ⚠️ Both ends must agree

The three formats are not interchangeable. A `Client` and `Server` in different
modes cannot talk. When changing the mode of a running system, either take a brief
outage or move through `'secure'` (which is wire-compatible with 0.0.8) while
rolling.

A mismatch is reported at both ends. The server logs one line and drops the
connection, the same way it already treats a routine disconnect:

```
Rejected connection: could not read frame as 'secure'. A Client and a Server must
use the same encryption mode -- check that both set the same value ...
```

and it answers the unreadable handshake with a plaintext note saying which mode it
is using, so the client raises `EncryptionMismatch` naming *both* sides rather than
a bare "connection closed":

```
bisocket.EncryptionMismatch: the server could not read this connection: the server
is using encryption 'secure' and this client is using 'faster'. Both ends must use
the same mode ...
```

`EncryptionMismatch` subclasses `ValueError`, which is what the codecs raised
before, so `except ValueError` keeps working.

Nothing was added to the bytes a client *sends*, so a client built from this
revision still handshakes with an older server exactly as before; against such a
server a mismatch simply reports itself the old way.

### What `'off'` gives up

With `encryption='off'` every frame goes out as plaintext, and a warning is printed
once to stderr. Anything on the network path can read *and modify* traffic: you lose
confidentiality and, because AES-GCM also authenticates, tamper detection. Only use
it where the whole path is trusted -- a private VPC subnet, a container network, or
loopback. `CRYPTO_KEY` is not read at all in this mode.

Frames are otherwise sent byte-for-byte, with one exception: a payload that happens
to contain the frame delimiter is base64-encoded so it cannot be mis-split. Each
frame carries a one-byte tag saying which of the two applies, so the common case
costs a single substring scan and one extra byte.

-----

## 🔐 Security

All data transmitted by `bisocket` is encrypted using **AES-256-GCM**, an authenticated encryption scheme that provides confidentiality and integrity. The 256-bit encryption key is derived from the string you provide via the `CRYPTO_KEY` environment variable using SHA-256.

**⚠️ It is crucial to set a strong, unique secret key for your application.**

You can generate a cryptographically secure key using OpenSSL:

```bash
# This command generates a 32-byte (256-bit) random key in hex format.
export CRYPTO_KEY=$(openssl rand -hex 32)
```

If `CRYPTO_KEY` is not set, a default, insecure key (`'secret-lol'`) is used and a warning is printed to stderr. This is intended **only for local testing and development**.

### Requiring a key

A warning in a long-running server's log is easy to miss, and the failure mode is
silent: the service comes up and runs happily on a publicly known key. Pass
`require_key=True` to make a missing `CRYPTO_KEY` a startup failure instead:

```python
from bisocket import Server, MissingCryptoKey

# Raises MissingCryptoKey right here if CRYPTO_KEY is unset.
server = Server('0.0.0.0', 65432, handler, require_key=True)
```

`Client` takes the same argument. Setting `BISOCKET_REQUIRE_KEY=1` in the
environment turns it on for both without a code change, which is the easy way to
harden a production image while leaving development alone:

```bash
export BISOCKET_REQUIRE_KEY=1
```

An explicit `require_key=` argument wins over the environment variable, so a test
harness inside a hardened image can still opt out. The requirement applies only
when encryption is actually on: with `encryption='off'` there is no key in play, so
`require_key=True` is accepted and ignored.

This section describes the `'secure'` and `'faster'` modes. With
`encryption='off'` there is no encryption at all and none of it applies.

Note the current limits of this model, which matter if you expose a server publicly:

  - Every client shares one symmetric key, so any client that can connect can read
    and forge any other client's traffic. There is no per-client authentication.
  - `client_id` is chosen by the client and is not verified.
  - The key is derived by a single SHA-256 pass, not a slow KDF, so a weak
    `CRYPTO_KEY` is cheap to brute force. Use a long random value.

-----

## 🧪 Running the tests

The suite drives real servers over loopback sockets, since that is the only place
the behaviour it covers actually exists.

```bash
pip install pytest && python -m pytest
```

-----

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

-----

## 🙏 Contributing

Contributions are welcome\! Please feel free to submit a pull request or open an issue to discuss new features or bugs.
