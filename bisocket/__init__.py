"""bisocket: simple, secure, bidirectional Python sockets.

The Cython build of the library (bisocket.cython.c_main) is used when it was
compiled at install time; otherwise the identical pure-Python bisocket.main is
used. Both are generated from the same source, so behaviour does not change.
"""

try:
    from .cython import c_main as main
except ImportError:
    from . import main

Client = main.Client
Server = main.Server
Message = main.Message
ServerRequest = main.ServerRequest
server_handler_example = main.server_handler_example

OnOpenInfo = main.OnOpenInfo
OnCloseInfo = main.OnCloseInfo
OnFinallyInfo = main.OnFinallyInfo
ConnectionLostInfo = main.ConnectionLostInfo

ConnectionClosed = main.ConnectionClosed
EncryptionMismatch = main.EncryptionMismatch
MissingCryptoKey = main.MissingCryptoKey
HandlerError = main.HandlerError
HandlerErrorInfo = main.HandlerErrorInfo

CONNECTION_SEND = main.CONNECTION_SEND
CONNECTION_RECEIVE = main.CONNECTION_RECEIVE
CONNECTION_TYPES = main.CONNECTION_TYPES

ENCRYPTION_SECURE = main.ENCRYPTION_SECURE
ENCRYPTION_FASTER = main.ENCRYPTION_FASTER
ENCRYPTION_OFF = main.ENCRYPTION_OFF
ENCRYPTION_MODES = main.ENCRYPTION_MODES
resolve_encryption = main.resolve_encryption
resolve_require_key = main.resolve_require_key

BiClient = main.BiClient
BiServer = main.BiServer
BiMessage = main.BiMessage
BiServerRequest = main.BiServerRequest

VERSION = main.VERSION
__version__ = main.VERSION

# Define the public API
__all__ = [
    'main',
    'Client', 'Server', 'Message', 'ServerRequest', 'server_handler_example',
    'BiClient', 'BiServer', 'BiMessage', 'BiServerRequest',
    'OnOpenInfo', 'OnCloseInfo', 'OnFinallyInfo', 'ConnectionLostInfo',
    'ConnectionClosed', 'EncryptionMismatch', 'MissingCryptoKey',
    'HandlerError', 'HandlerErrorInfo',
    'CONNECTION_SEND', 'CONNECTION_RECEIVE', 'CONNECTION_TYPES',
    'ENCRYPTION_SECURE', 'ENCRYPTION_FASTER', 'ENCRYPTION_OFF', 'ENCRYPTION_MODES',
    'resolve_encryption', 'resolve_require_key',
    'VERSION', '__version__',
]
