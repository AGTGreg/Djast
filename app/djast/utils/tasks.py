from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any


async def run_in_executor(func: Callable[..., Any], *args: Any) -> Any:
    """Run a sync/CPU-bound function in the default thread-pool executor.

    Use this inside Taskiq tasks that need to call blocking code::

        @broker.task
        async def heavy_computation(data: str) -> str:
            return await run_in_executor(cpu_intensive_func, data)
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)
