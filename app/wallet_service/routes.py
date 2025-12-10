import secrets
import hmac
import hashlib
import json
from datetime import datetime
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request
from paystack.resource import TransactionResource
from typing import List
from sqlalchemy.orm import Session, joinedload

from app.core.config import config, logger
from app.core.db import get_db
from .models import User, APIKey, Wallet, Transaction
from .auth import creat_user_account, create_user_api_key, get_current_actor
from .schemas import (CreateAPIKeyRequest, RolloverAPIKeyRequest, 
                      APIKeyResponse, DepositRequest, WalletPermission, 
                      TransactionStatus, TransactionType, TransferRequest,
                      TransactionResponse)
from .utils import has_permission, create_transaction, update_transaction, make_transfer
from .exception_handler import AccountSetUpError, TransferError

router = APIRouter()


oauth = OAuth()
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id=config.GOOGLE_CLIENT_ID,
    client_secret=config.GOOGLE_CLIENT_SECRET,
    client_kwargs = {
        'scope': 'openid email profile',
        'redirect_uri': config.GOOGLE_REDIRECT_URI

    },
)



@router.get("/auth/google")
async def auth_google(request: Request):
    """Redirect user to Google OAuth2 authorization endpoint.
    Initiates the Google OAuth2 authorization flow by redirecting
    the user to Google's authorization server. The user will be prompted to authenticate
    and grant permissions to the application.
    """
    return await oauth.google.authorize_redirect(request, config.GOOGLE_REDIRECT_URI)


@router.get("/auth/google/callback")
async def auth_google_callback(request: Request, db: Session = Depends(get_db)):
    """ Handle Google OAuth callback and authenticate user.
    Processes the Google OAuth callback, extracts user information
    from the OAuth token, creates a user account in the database if it doesn't exist,
    and returns a JWT token for authentication.
    """
    try:
        user_token = await oauth.google.authorize_access_token(request)
        logger.info("token generated", user_token=user_token)
        userinfo = user_token.get('userinfo')
        await creat_user_account(userinfo, db)
        jwt_token = user_token.get('id_token')
        return {"jwt_token": jwt_token}
    except AccountSetUpError as setup_error:
        db.rollback() 
        raise setup_error
    except:
        raise HTTPException(status_code=500, detail="Google signin Auth Failed")



@router.post("/keys/create", response_model=APIKeyResponse)
async def create_api_key(
    req: CreateAPIKeyRequest, 
    user: User = Depends(get_current_actor), 
    db: Session = Depends(get_db),
):
    """
    Create a new API key for the authenticated user.
    This endpoint allows users to generate a new API key for programmatic access.
    Users are limited to a maximum of 5 active (non-revoked, non-expired) API keys.
    Args:
        req (CreateAPIKeyRequest): Request object containing API key creation details.
    Returns:
        APIKeyResponse: The newly created API key with its details.
    Raises:
        HTTPException: 400 Bad Request if the user already has 5 or more active API keys.
    Example:
        POST /api/keys
        {
            "name": "Production API Key",
            "expires_in: 1H  # "1H", "1D", "1M", "1Y"
        }
    """
    logger.info("current user is", current_user=user)
    if not user or isinstance(user, tuple):
        raise HTTPException(status_code=400, detail="Unathorized requires jwt Auth")
    active_keys = db.query(APIKey).filter(APIKey.user_id == user.id, APIKey.revoked == False, APIKey.expires_at > datetime.utcnow()).count()
    if active_keys >= 5:
        raise HTTPException(status_code=400, detail="Max 5 active API keys")

    api_key_response = await create_user_api_key(user.id, req, db)

    return api_key_response


@router.post("/keys/rollover", response_model=APIKeyResponse)
async def rollover_api_key(
    req: RolloverAPIKeyRequest, 
    user: User = Depends(get_current_actor), 
    db: Session = Depends(get_db)
):
    """Rollover an expired API key for a user.
    checks if the provided API key has expired and, if so, generates a new API key for the user. 
    Parameters:
        req (RolloverAPIKeyRequest): The request object containing the expired API key ID.
    """
    if not user or isinstance(user, tuple):
        raise HTTPException(status_code=400, detail="Unathorized requires jwt Auth")
    old_key = db.query(APIKey).filter(APIKey.key == req.expired_key_id, APIKey.user_id == user.id).first()
    if not old_key or old_key.expires_at >= datetime.utcnow():
        raise HTTPException(status_code=400, detail="Key not expired or invalid")
   
    api_key_response = await create_user_api_key(user.id, req, db, old_key=old_key)

    return api_key_response



@router.post("/wallet/deposit")
async def deposit(req: DepositRequest, db: Session = Depends(get_db), auth=Depends(get_current_actor)):
    """Initiate a deposit transaction for a user's wallet.
    Handles wallet deposit requests by initializing a payment transaction with Paystack payment gateway.
    Args:
        req (DepositRequest): The deposit request containing the amount to deposit.        
    Returns:
        dict: A dictionary containing:
            - reference (str): Unique transaction reference ID for tracking.
            - authorization_url (str): Paystack authorization URL for payment completion.
    Raises:
        HTTPException: 
            - 400 Bad Request: If Paystack transaction initialization fails.
            - 500 Internal Server Error: If an unexpected error occurs during processing.
    """
    if isinstance(auth, tuple):  # API key
        user, permissions = auth
        has_permission(permissions, WalletPermission.DEPOSIT)
    else:
        user = auth
    reference = secrets.token_hex(8)
    try:
        transaction = TransactionResource(config.PAYSTACK_SECRET_KEY)
        response = transaction.initialize(amount=req.amount * 100, email=user.email, ref=reference)  # Paystack uses kobo
        if response['status']:
            await create_transaction(user.wallet.id, req.amount, TransactionType.DEPOSIT, reference, db)
            return {"reference": reference, "authorization_url": response['data']['authorization_url']}
        else:
            raise HTTPException(status_code=400, detail="Paystack initialization failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.post("/wallet/paystack/webhook")
async def paystack_webhook(request: Request, db: Session = Depends(get_db)):
    """Handle Paystack webhook notifications for transaction events.
    Receives and processes webhook events from Paystack payment gateway.
    It validates the webhook signature using HMAC-SHA512 to ensure the request authenticity,
    then processes successful charge events by updating the corresponding transaction records.
    Args:
        request (Request): The incoming HTTP request containing the webhook payload and signature.
    Returns:
        dict: A dictionary with status True indicating successful webhook processing.
    """

    payload = await request.body()
    signature = request.headers.get('x-paystack-signature')
    if not signature:
        raise HTTPException(status_code=400, detail="Missing signature")
    
    computed_sig = hmac.new(config.PAYSTACK_SECRET_KEY.encode(), payload, hashlib.sha512).hexdigest()
    if signature != computed_sig:
        raise HTTPException(status_code=400, detail="Invalid signature")
    event = json.loads(payload)
    logger.info("Paystack transaction event", event_details=event)
    if event['event'] == 'charge.success':
        reference = event['data']['reference']
        await update_transaction(db, reference)
    return {"status": True}


@router.get("/wallet/deposit/{reference}/status")
def get_deposit_status(reference: str, auth = Depends(get_current_actor), db: Session = Depends(get_db)):
    """
    Retrieve the deposit status of a transaction by reference.
    Args:
        reference (str): The unique reference identifier of the transaction to check.
    Returns:
        dict: A dictionary containing:
            - reference (str): The transaction reference identifier.
            - status (str): The current status of the transaction (from Paystack or database).
            - amount (float): The transaction amount.
    Note:
        - For API key authentication, verifies READ permission on wallet operations.
        - Attempts to verify transaction status via Paystack API; falls back to 
          database status if verification fails.
    """

    if isinstance(auth, tuple):  # API key
        user, permissions = auth
        has_permission(permissions, WalletPermission.READ)
    else:
        user = auth
    txn = db.query(Transaction).filter(Transaction.reference == reference, Transaction.wallet_id == user.wallet.id).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    try:
        response = TransactionResource(config.PAYSTACK_SECRET_KEY).verify(reference)
        status = response['data']['status']
    except:
        status = txn.status
    return {"reference": reference, "status": status, "amount": txn.amount}



@router.post("/wallet/transfer")
async def transfer(req: TransferRequest, db: Session = Depends(get_db), auth=Depends(get_current_actor)):
    """Transfersfunds from the authenticated user's wallet to a recipient.
    Args:
        req (TransferRequest): Transfer request object containing the recipient's wallet number and transfer amount.
    Returns:
        dict: A dictionary with status and message indicating successful transfer completion.
    """

    if isinstance(auth, tuple):
        user, permissions = auth
        has_permission(permissions, WalletPermission.TRANSFER)
    else:
        user = auth
    if user.wallet.balance < req.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    recipient_wallet = db.query(Wallet).filter(Wallet.wallet_number == req.wallet_number).first()
    if not recipient_wallet:
        raise HTTPException(status_code=404, detail="Recipient not found")
    try:
        await make_transfer(user, req, recipient_wallet, db)
        return {"status": "success", "message": "Transfer completed"}
    except TransferError as transer_error:
        db.rollback() #
        raise transer_error
    except Exception as e:
        logger.info("Error sending transfer", error=e)
        raise HTTPException(status_code=500, detail="Transfer failed")


@router.get("/wallet/transactions", response_model=List[TransactionResponse])
def get_transactions(db: Session = Depends(get_db), auth=Depends(get_current_actor)):
    """Retrieve all transactions for the authenticated user's wallet.
    Fetches all transactions associated with the current user's wallet
    from the database. 
    Returns:
        list[dict]: A list of transaction dictionaries, each containing:
            - type (str): The type of transaction
            - amount (float): The transaction amount
            - status (str): The current status of the transaction
    """
    if isinstance(auth, tuple):
        user, permissions = auth
        has_permission(permissions, WalletPermission.READ)
    else:
        user = auth
    txns = db.query(Transaction).filter(Transaction.wallet_id == user.wallet.id).all()
    return [{"type": t.type, "amount": t.amount, "status": t.status} for t in txns]



@router.get("/wallet/balance")
def get_balance(db: Session = Depends(get_db), auth=Depends(get_current_actor)):
    """
    Retrieve the wallet balance for the authenticated user.
    Returns:
        dict: A dictionary containing the user's wallet balance.
            Example: {"balance": 1000.50}
    Raises:
        PermissionError: If the user lacks the READ permission for wallet operations.
    """
    if isinstance(auth, tuple):
        user, permissions = auth
        logger.info("is instance of tuple", user=user)
        has_permission(permissions, WalletPermission.READ)
    else:
        user = auth
    return {"balance": user.wallet.balance}
    



@router.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    """
    Retrieve all users with their associated wallet and API key information.
    This function queries the database for all User records and eagerly loads
    their related wallet and api_keys data using joinedload to optimize query.

    Returns:
        list[dict]: A list of dictionaries containing user information with the following structure:
            - id (int): The user's unique identifier.
            - email (str): The user's email address.
            - full_name (str): The user's full name.
            - wallet (dict): User's wallet information containing:
                - id (int | None): The wallet's unique identifier, or None if no wallet exists.
                - wallet (str | None): The wallet number, or None if no wallet exists.
                - balance (float): The wallet's current balance, defaults to 0 if no wallet exists.
            - api_keys (list[dict]): List of API keys associated with the user, each containing:
                - id (int): The API key's unique identifier.
                - key (str): The actual API key string.
                - expires_at (datetime | None): The expiration timestamp of the API key.
                - permissions (str | list): The permissions granted to this API key.
    Raises:
        SQLAlchemyError: If a database query error occurs.
    """

    users = (
        db.query(User)
        .options(
            joinedload(User.wallet),
            joinedload(User.api_keys)
        )
        .all()
    )

    return [
        {
            "id": user.id,
            "email": user.email,
            "full_name": user.name,
            "wallet": {
                "id": user.wallet.id if user.wallet else None,
                "wallet": user.wallet.wallet_number if user.wallet  else None,
                "balance": user.wallet.balance if user.wallet else 0,
            },
            "api_keys": [
                {
                    "id": key.id,
                    "key": key.key,
                    "expires_at": key.expires_at,
                    "permissions": key.permissions
                } for key in user.api_keys
            ]
        }
        for user in users
    ]