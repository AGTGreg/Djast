from taskiq import TaskiqScheduler
from taskiq.schedule_sources import LabelScheduleSource

from djast.taskiq import broker

scheduler = TaskiqScheduler(
    broker=broker,
    sources=[LabelScheduleSource(broker)],
)
