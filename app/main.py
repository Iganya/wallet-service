from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.middleware.sessions import SessionMiddleware

from .core.db import engine, Base
from .wallet_service import routes 
from .core.config import config

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,  # Or another status code
        content={"error": "Validation failed"},
        )


app.include_router(routes.router)


@app.get("/health")
async def health_check():
    return {"status": "ok"}
