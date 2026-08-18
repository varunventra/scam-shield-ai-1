"""
Single shared rate limiter instance.

Both the route decorators and the RateLimitExceeded handler must use the SAME
Limiter object: the handler reads ``request.app.state.limiter`` while the
decorator enforces against its own ``_route_limits``, so two separate instances
let configuration diverge without any error.

Storage is in-process. Limits therefore reset on restart and are per-worker --
set ``RATELIMIT_STORAGE_URI`` to a Redis URL before running more than one
worker.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["120/minute"],
)
