# # Import modules from subpackages
# try:
#     from .cython import c_main as main 
# except:
#     from . import main

# try:
#     from .cython.c_main import (
#         Client, Server, Message, ServerRequest, server_handler_example,
#         BiClient, BiServer, BiMessage, BiServerRequest
#     )
# except:
#     from .main import (
#         Client, Server, Message, ServerRequest, server_handler_example,
#         BiClient, BiServer, BiMessage, BiServerRequest
#     )

from . import main

from .main import (
    Client, Server, Message, ServerRequest, server_handler_example,
    BiClient, BiServer, BiMessage, BiServerRequest
)

# Define the public API
__all__ = [
    'main',
]
