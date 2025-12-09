from uuid import uuid4
from app.core.db import Base
from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, DateTime, JSON
from sqlalchemy.orm import relationship
from .schemas import TransactionStatus
from datetime import datetime


class User(Base):
    __tablename__ = "users"
    id = Column(String, unique=True, index=True, primary_key=True)
    name = Column(String,  index=True)
    email = Column(String, unique=True, index=True)
    wallet = relationship("Wallet", back_populates="user", uselist=False)
    api_keys = relationship("APIKey", back_populates="user")



class Wallet(Base):
    __tablename__ = "wallets"
    id = Column(String(255), primary_key=True, default=lambda: str(uuid4()), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    balance = Column(Float, default=0.0)
    wallet_number = Column(String, unique=True, index=True)  # Generated unique number
    user = relationship("User", back_populates="wallet")
    transactions = relationship("Transaction", back_populates="wallet")


class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()), nullable=False, index=True)
    wallet_id = Column(String, ForeignKey("wallets.id"))
    type = Column(String)  # "deposit" or "transfer"
    amount = Column(Float)
    status = Column(String, default=TransactionStatus.PENDING) 
    reference = Column(String, unique=True, index=True)  # For Paystack or internal
    timestamp = Column(DateTime, default=datetime.utcnow)
    wallet = relationship("Wallet", back_populates="transactions")


class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    key = Column(String, unique=True, index=True)  # Generated key
    name = Column(String)
    permissions = Column(JSON)  # List of strings
    expires_at = Column(DateTime)
    revoked = Column(Boolean, default=False)
    user = relationship("User", back_populates="api_keys")