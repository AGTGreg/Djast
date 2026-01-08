from slowapi import Limiter
from slowapi.util import get_remote_address
from djast.settings import settings


limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.RATE_LIMIT_REDIS_URL,
    default_limits=[],  # No global default limits, explicit only
)
