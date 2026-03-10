from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from djast.settings import settings
from djast.urls import api_router
from djast.utils.csrf import csrf_protect


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        debug=settings.DEBUG,
        dependencies=[Depends(csrf_protect)],
    )

    from djast.rate_limit import limiter
    from slowapi.middleware import SlowAPIMiddleware
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOW_ORIGINS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    )

    app.include_router(api_router, prefix=settings.APP_PREFIX)

    return app


app = create_app()
