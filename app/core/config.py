import os
import sys
import logging
import structlog
from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from functools import lru_cache

load_dotenv()


class Settings(BaseSettings):
    # DB_USERNAME: str = os.getenv("DB_USERNAME")
    # DB_PASSWORD: str = os.getenv("DB_PASSWORD")
    # DB_HOSTNAME: str = os.getenv("DB_HOSTNAME")
    # DB_PORT: str = os.getenv("DB_PORT")
    # DB_DATABASE: str = os.getenv("DB_DATABASE")
    DB_URL: str = os.getenv('WALLET_SERVICE_DB_URL')

    SECRET_KEY: str = os.getenv("SECRET_KEY")
    ALGORITHM: str = os.getenv("ALGORITHM")
    
    PAYSTACK_SECRET_KEY: str = os.getenv("PAYSTACK_SECRET_KEY")
    PAYSTACK_PUBLIC_KEY: str = os.getenv("PAYSTACK_PUBLIC_KEY")

    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_CERTS_URL: str = os.getenv("GOOGLE_CERTS_URL")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI")



@lru_cache() # Caches settings for performance, avoids loading .env repeatedly
def get_settings():
    return Settings()

    
config = get_settings()


# Logging Configuration
logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=logging.INFO,
)

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.CallsiteParameterAdder(
            [
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            ]
        ),
        structlog.dev.ConsoleRenderer(),
    ],
)

logger = structlog.get_logger()