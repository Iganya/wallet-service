from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .core.db import engine, Base
from .wallet_service import routes 
from .core.config import config

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Wallet Service with Google Auth Signin")

app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def custom_validation_handler(request: Request, exc: RequestValidationError):
    errors = []

    for err in exc.errors():
        field_path = ".".join(str(loc) for loc in err["loc"] if loc != "body")

        errors.append({
            "field": field_path,
            "message": err.get("msg", "Invalid input") #pydantic default message
        })

    return JSONResponse(
        status_code=422,
        content={"errors": errors}
    )


app.include_router(routes.router)


@app.get("/health")
async def health_check():
    return {"status": "ok"}
