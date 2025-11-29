from djast.settings import settings
from datetime import datetime
from zoneinfo import ZoneInfo


def now() -> datetime:
    return datetime.now(ZoneInfo(settings.TIME_ZONE))
