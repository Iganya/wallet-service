import secrets
from typing import List
from fastapi import HTTPException
from app.core.config import logger
from .models import Transaction, Wallet
from .schemas import TransactionType, TransactionStatus
from .exception_handler import TransferError



class PermissionError(Exception):
    pass

def has_permission(permissions: List[str], required: str):
    """
    Check if a required permission exists in a list of api key permissions.
    Args:
        permissions (List[str]): A list of permission strings to check against.
        required (str): The required permission string to verify.
    Raises:
        HTTPException: 403 permission error.
    Returns:
        None: 
    """
    if required not in permissions:
        raise HTTPException(status_code=403, detail=f"Missing permission: {required}")
    


async def create_transaction(wallet_id, amount, transaction_type, reference, db):
    """Create Transaction on deposite"""
    txn = Transaction(wallet_id=wallet_id, type=transaction_type, amount=amount, reference=reference)
    db.add(txn)
    db.commit()


async def update_transaction(db, reference):
    txn = db.query(Transaction).filter(Transaction.reference == reference).first()
    if txn and txn.status != "success":  # Idempotency
        txn.status = TransactionStatus.SUCCESS
        wallet = db.query(Wallet).filter(Wallet.id == txn.wallet_id).first()
        wallet.balance += txn.amount
        db.commit()


async def make_transfer(user, amount, recipient_wallet, db):
    """Perform a transfer transaction between two wallets.
    Create atomic transaction to update both wallet balances record the transaction.
    Args:
        user: The user object initiating the transfer, must have a wallet attribute.
        amount: The transfer amount.
        recipient_wallet: The wallet object of the transfer recipient.
        db: The database session object for committing changes.
    Returns:
        None
    """
    try:
        user.wallet.balance -= amount
        recipient_wallet.balance += amount
        ref = secrets.token_hex(8)
        sender_txn = Transaction(
                wallet_id=user.wallet.id, 
                type=TransactionType.TRANSFER, 
                amount=-amount, 
                status=TransactionStatus.SUCCESS, 
                reference=ref
            )
        receiver_txn = Transaction(
                wallet_id=recipient_wallet.id, 
                type=TransactionType.TRANSFER, 
                amount=amount, 
                status=TransactionStatus.SUCCESS, 
                reference=f"{ref}-{sender_txn.id}"
            )
        
        db.add(sender_txn)
        db.add(receiver_txn)
        db.commit()
    except Exception as e:
        logger.info("Transfer Error", error=e)
        raise TransferError(status_code=400, detail="Error Processing Transfer")