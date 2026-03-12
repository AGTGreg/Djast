from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from taskiq import InMemoryBroker

from djast.settings import settings

if TYPE_CHECKING:
    from taskiq_redis import ListQueueBroker

logger = logging.getLogger(__name__)


def _build_broker() -> InMemoryBroker | ListQueueBroker:
    """Build the Taskiq broker from settings.

    Returns an ``InMemoryBroker`` when the URL is empty or set to
    ``"memory://"`` (useful for testing).  Otherwise returns a Redis-backed
    ``ListQueueBroker`` with result backend and retry middleware.
    """
    url = settings.TASKIQ_BROKER_URL
    if not url or url == "memory://":
        return InMemoryBroker()

    from taskiq.middlewares.smart_retry_middleware import SmartRetryMiddleware
    from taskiq_redis import ListQueueBroker, RedisAsyncResultBackend

    result_backend = RedisAsyncResultBackend(
        redis_url=settings.TASKIQ_RESULT_BACKEND_URL,
        result_ex_time=settings.TASKIQ_RESULT_EX_TIME,
    )

    _broker = ListQueueBroker(url=url).with_result_backend(result_backend)

    if settings.TASKIQ_RETRY_MAX_ATTEMPTS > 0:
        _broker = _broker.with_middlewares(
            SmartRetryMiddleware(
                default_retry_count=settings.TASKIQ_RETRY_MAX_ATTEMPTS,
                default_delay=settings.TASKIQ_RETRY_DELAY,
                use_jitter=True,
                use_delay_exponent=True,
                max_delay_exponent=settings.TASKIQ_RETRY_MAX_DELAY,
            ),
        )

    return _broker


broker = _build_broker()


def _reset_broker() -> None:
    """Replace the broker with an ``InMemoryBroker`` (used by tests)."""
    global broker
    broker = InMemoryBroker()
