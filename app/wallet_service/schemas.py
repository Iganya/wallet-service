from enum import Enum
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class TransactionStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"

class WalletPermission(str, Enum):
    DEPOSIT = "deposit"
    TRANSFER = "transfer"
    READ = "read"

class TransactionType(str, Enum):
    DEPOSIT = "deposit"
    TRANSFER = "transfer"


class CreateAPIKeyRequest(BaseModel):
    name: str
    permissions: List[str]
    expiry: str  # "1H", "1D", "1M", "1Y"


class RolloverAPIKeyRequest(BaseModel):
    expired_key_id: str
    expiry: str

class TransferRequest(BaseModel):
    wallet_number: str
    amount: float

    
class DepositRequest(BaseModel):
    amount: float


class APIKeyResponse(BaseModel):
    api_key: str
    expires_at: datetime

class TransactionResponse(BaseModel):
    type: str
    amount: float
    status: str

