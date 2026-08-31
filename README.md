# `bisocket`: Simple, Secure, Bidirectional Python Sockets

[![PyPI](https://img.shields.io/pypi/v/bisocket.svg)](https://pypi.org/project/bisocket/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`bisocket` is a high-level Python library that simplifies bidirectional (two-way) communication over sockets. It provides a robust framework for building client-server applications that require sending and receiving data simultaneously without blocking.

It comes with built-in **AES-GCM end-to-end encryption** and **bz2 compression**, ensuring your data is secure and transmitted efficiently. The library offers both synchronous (threading-based) and asynchronous (`asyncio`) APIs, making it versatile for various application architectures.

-----

## ✨ Features

  - **True Bidirectional Communication**: Uses separate sockets for sending and receiving, enabling non-blocking, full-duplex communication.
  - **End-to-End Encryption**: Automatic AES-GCM encryption for all messages ensures data privacy and integrity.
  - **Data Compression**: Automatic `bz2` compression reduces bandwidth usage for large payloads.
  - **Sync & Async Support**: Provides both a standard threading API and a modern `asyncio` API.
  - **Simple Handler-Based API**: Use a clean handler function on the server and an `on_receive` callback on the client to process messages.
  - **Unique Client Identification**: Manages clients using unique UUIDs, making it easy to track connections.
  - **Connection Lifecycle Hooks**: Optional `on_open`, `on_close` and `on_finally` callbacks on the server.

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

### `Client(host, port, on_receive)`

`on_receive` is called with a `Message` for every message pushed by the server. It
may be a normal function or an `async def` coroutine function.

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

### `Server(host, port, handler, ...)`

| Argument | Called when |
| --- | --- |
| `handler` | A request arrives. Receives a `ServerRequest`. |
| `on_open` | A client's send socket connects. Receives `OnOpenInfo`. |
| `on_open_receive` | A client's receive socket connects. Receives `OnOpenInfo`. |
| `on_close` | A client's send socket closes. Receives `OnCloseInfo`. |
| `on_close_receive` | A client's receive socket closes. Receives `OnCloseInfo`. |
| `on_finally` | Any client connection ends, for any reason. Receives `OnFinallyInfo`. |

Every callback, and `handler` itself, may be a normal function or an `async def`
coroutine function. `OnOpenInfo` and `OnCloseInfo` carry a `client_id`;
`OnFinallyInfo` carries `client_id: str | None`, which is `None` if the connection
failed before the client identified itself.

Because each client opens two sockets, `on_finally` fires twice per client — once
per connection.

| Method | Description |
| --- | --- |
| `start()` | Run the threaded server. Blocks forever. |
| `astart()` | Run the asyncio server. Blocks forever. |

### `ServerRequest`

| Attribute / Method | Description |
| --- | --- |
| `client_id: str` | UUID of the sending client. |
| `request_id: str` | UUID of this request. |
| `method: str` | Method name the client sent. |
| `data: bytes` | Raw payload. |
| `send_data(data: bytes)` | Queue a `bytes` response back to that client. |
| `send(data: str)` | Same, for a `str`. |

A handler may call `send_data()` any number of times, including zero. Responses are
pushed over the client's receive socket, so they are not tied to a request/response
turn.

### Aliases

`BiClient`, `BiServer`, `BiMessage` and `BiServerRequest` are aliases for `Client`,
`Server`, `Message` and `ServerRequest`.

-----

## 🧠 How It Works

Traditional socket programming can be tricky when you need to send and receive data at the same time, often leading to blocking calls or complex multiplexing.

`bisocket` simplifies this by establishing **two separate socket connections** for each client:

1.  **Send Socket**: The client uses this connection exclusively to send data *to* the server.
2.  **Receive Socket**: The client uses this connection exclusively to receive data *from* the server.

This architecture allows the client and server to communicate in full-duplex mode without one operation blocking the other. The library manages these connections, message framing, encryption, and compression internally, so you can focus on your application logic.

  - **On the Client**: The `Client` runs a background thread (or `asyncio` task) to listen for incoming messages on the receive socket. These messages are passed to your `on_receive` callback.
  - **On the Server**: The `Server` manages a pool of client connections. It receives a request from a client's "send" socket, processes it in your handler, and then queues the response to be sent back via that same client's "receive" socket.

Messages are delimited on the wire by a byte token. Payloads are encrypted and
compressed before framing, so your own data may contain any bytes, delimiters
included.

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

Note the current limits of this model, which matter if you expose a server publicly:

  - Every client shares one symmetric key, so any client that can connect can read
    and forge any other client's traffic. There is no per-client authentication.
  - `client_id` is chosen by the client and is not verified.
  - The key is derived by a single SHA-256 pass, not a slow KDF, so a weak
    `CRYPTO_KEY` is cheap to brute force. Use a long random value.

-----

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

-----

## 🙏 Contributing

Contributions are welcome\! Please feel free to submit a pull request or open an issue to discuss new features or bugs.
