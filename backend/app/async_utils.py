from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, TypeVar


T = TypeVar("T")


async def run_blocking(func: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
    """Run blocking I/O or CPU-light sync code without pinning the event loop."""
    return await asyncio.to_thread(func, *args, **kwargs)
