# Task Queue (Taskiq)

Djast uses [Taskiq](https://taskiq-python.github.io/) as its async-native task queue, backed by Redis.

## Configuration

All settings live in `djast/settings.py` and can be overridden via environment variables:

| Setting | Default | Description |
|---------|---------|-------------|
| `TASKIQ_BROKER_URL` | `redis://redis:6379/3` | Redis URL for the task broker |
| `TASKIQ_RESULT_BACKEND_URL` | `redis://redis:6379/4` | Redis URL for task results |
| `TASKIQ_RESULT_EX_TIME` | `3600` | Result expiry time in seconds |
| `TASKIQ_RETRY_MAX_ATTEMPTS` | `3` | Max retry attempts (0 to disable) |
| `TASKIQ_RETRY_DELAY` | `5.0` | Base delay between retries (seconds) |
| `TASKIQ_RETRY_MAX_DELAY` | `120.0` | Max delay cap for exponential backoff (seconds) |
| `EMAIL_USE_TASKIQ` | `False` | Route emails through the task queue |

## Defining Tasks

Tasks live in `tasks.py` within each app module. The broker is imported from `djast.taskiq`:

```python
# myapp/tasks.py
from djast.taskiq import broker


@broker.task
async def process_order(order_id: int) -> str:
    # your async logic here
    return f"Processed order {order_id}"
```

### Calling Tasks from Views

Use `.kiq()` to enqueue a task from an endpoint:

```python
from myapp.tasks import process_order


@router.post("/orders/{order_id}/process")
async def trigger_processing(order_id: int):
    task = await process_order.kiq(order_id)
    return {"task_id": task.task_id}
```

### Getting Task Results

```python
task = await process_order.kiq(order_id)
result = await task.wait_result(timeout=10)

if result.is_err:
    print(f"Task failed: {result.return_value}")
else:
    print(f"Result: {result.return_value}")
    print(f"Execution time: {result.execution_time}s")
```

## Cron / Scheduled Tasks

Djast includes a built-in scheduler. Add cron schedules directly on task decorators:

```python
@broker.task(schedule=[{"cron": "0 3 * * *"}])
async def daily_cleanup():
    """Runs every day at 3 AM UTC."""
    ...


@broker.task(schedule=[{"cron": "*/5 * * * *", "args": [100]}])
async def check_thresholds(limit: int):
    """Runs every 5 minutes with limit=100."""
    ...
```

The scheduler is run as a separate process (see [Running Workers](#running-workers) below).

## CPU-Bound Tasks

For blocking or CPU-intensive work inside async tasks, use `run_in_executor`:

```python
from djast.taskiq import broker
from djast.utils.tasks import run_in_executor


def heavy_computation(data: str) -> str:
    # CPU-intensive sync code
    return data.upper() * 1000


@broker.task
async def process_data(data: str) -> str:
    return await run_in_executor(heavy_computation, data)
```

## Retry Behaviour

Tasks use `SmartRetryMiddleware` with exponential backoff and jitter by default. Configure globally via settings or per-task:

```python
@broker.task(retry_on_error=True, max_retries=5)
async def fragile_task():
    ...
```

Set `TASKIQ_RETRY_MAX_ATTEMPTS=0` to disable retries globally.

## Email Integration

When `EMAIL_USE_TASKIQ=True`, emails sent via `send_email()` and `send_template_email()` are dispatched through the task queue instead of being sent inline. This means endpoints return immediately without waiting for SMTP.

**Important limitations:**

- **Console backend is never affected.** When `EMAIL_BACKEND` is the console backend, emails are always sent directly regardless of the `EMAIL_USE_TASKIQ` setting. This keeps development simple.

- **Attachments are not supported with Taskiq.** Binary attachment data cannot be efficiently serialised through Redis. If you call `send_email()` with attachments while `EMAIL_USE_TASKIQ=True` (and a non-console backend), a `ValueError` is raised:

  ```
  ValueError: Email attachments are not supported when EMAIL_USE_TASKIQ
  is enabled. Either send without attachments or set EMAIL_USE_TASKIQ=False.
  ```

  To send emails with attachments, set `EMAIL_USE_TASKIQ=False` or remove the attachments.

## Running Workers

### Docker Compose (recommended)

The `docker-compose.yaml` includes `taskiq-worker` and `taskiq-scheduler` services. They start automatically with `docker compose up`.

### Manual

```bash
cd app

# Start a worker (processes tasks)
taskiq worker djast.taskiq:broker djast.tasks myapp.tasks --reload

# Start the scheduler (dispatches cron tasks)
taskiq scheduler djast.scheduler:scheduler --reload
```

Add all your app task modules to the worker command so tasks are discovered.

### Worker CLI Flags

| Flag | Description |
|------|-------------|
| `--workers N` | Number of child worker processes (default: 2) |
| `--max-async-tasks N` | Max simultaneous async tasks per worker |
| `--reload` | Auto-reload on code changes (dev only) |

## Testing

Tests use `InMemoryBroker` which requires no Redis. The `_reset_broker()` function swaps the broker for tests:

```python
import pytest
from djast.taskiq import _reset_broker


@pytest.fixture(autouse=True)
def _reset():
    _reset_broker()
    yield
    _reset_broker()


@pytest.mark.asyncio
async def test_my_task():
    from myapp.tasks import my_task

    # Call the task function directly (not via .kiq())
    result = await my_task(arg="value")
    assert result == expected
```

To test that a view enqueues a task, mock the task's `.kiq()` method:

```python
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_view_enqueues_task():
    mock_kiq = AsyncMock()
    with patch("myapp.tasks.my_task.kiq", mock_kiq):
        response = await client.post("/endpoint")
        assert response.status_code == 200
        mock_kiq.assert_called_once_with(expected_arg)
```
