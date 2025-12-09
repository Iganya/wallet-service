from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import config





DB_URL = config.DB_URL
# if not DB_URL:
#     DB_URL = f"postgresql://{config.DB_USERNAME}:{config.DB_PASSWORD}@{config.DB_HOSTNAME}:{config.DB_PORT}/{config.DB_DATABASE}"
 
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Database session dependency for database operations"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()