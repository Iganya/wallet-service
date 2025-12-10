
import secrets
from uuid import uuid4
from jose import jwt
from jose.exceptions import ExpiredSignatureError
from fastapi import Depends, HTTPException, Request, status, Security
from app.core.db import get_db

from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from app.core.config import config, logger
from .models import User, Wallet, APIKey
from .schemas import APIKeyResponse
from .exception_handler import APIKeyError, JWTExpiredSignatureError, AccountSetUpError
import requests
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader


jwt_scheme = HTTPBearer(auto_error=False)
api_key_scheme = APIKeyHeader(name="x-api-key", auto_error=False)



def decode_google_token(token: str, db):
    try:
        # 1. Get Google's public keys
        jwks = requests.get(config.GOOGLE_CERTS_URL).json()

        # 2. Decode and verify
        header = jwt.get_unverified_header(token)
        kid = header["kid"]

        # 3. Find the matching key
        key = next(k for k in jwks["keys"] if k["kid"] == kid)

        # 4. Decode + verify token
        decoded = jwt.decode(
            token,
            key,
            algorithms=[config.ALGORITHM],
            audience=config.GOOGLE_CLIENT_ID,
            issuer="https://accounts.google.com",
            options={
            "verify_at_hash": False
        }
        )
        user_id: str = decoded.get("sub")
        user = get_user_with_user_id(user_id, db)
        return user
    except ExpiredSignatureError:
        raise JWTExpiredSignatureError(status_code=401, detail="Token Expired")
    except Exception as e:
        logger.info("Error Decoding google token", error=e)


def verify_api_key(token, db):
    api_key = db.query(APIKey).filter(APIKey.key == token, APIKey.revoked == False, APIKey.expires_at > datetime.utcnow()).first()
    if not api_key:
        raise APIKeyError(status_code=401, detail="Invalid API Key or Expired API key")
    return api_key.user, api_key.permissions
    

def get_current_actor(
    db: Session = Depends(get_db),
    jwt_credentials: HTTPAuthorizationCredentials = Security(jwt_scheme),
    api_key: str = Security(api_key_scheme)
):
    """
    Retrieve the current authenticated actor (user) from the request.
    This function attempts to authenticate the request using two methods in order:
    1. JWT (JSON Web Token) - via Google token validation
    2. API Key - via API key verification
    Args:
        db (Session): Database session dependency for querying user and API key data.
        jwt_credentials (HTTPAuthorizationCredentials): JWT credentials from the Authorization header.
        api_key (str): API key from the request (header or query parameter).
    Returns:
        User: The authenticated user object if JWT authentication succeeds.
        tuple: A tuple of (User, permissions) if API key authentication succeeds.
    Raises:
        APIKeyError: If API key validation fails.
        JWTExpiredSignatureError: If the JWT token has expired.
        HTTPException: If authentication fails or credentials are invalid/missing (status 401).
    """
    try:
        logger.info("Getting current user")
        if not jwt_credentials and not api_key:
            raise HTTPException(status_code=401, detail="Missing authentication credentials")
        # Try JWT 
        if jwt_credentials:
            token = jwt_credentials.credentials
            user = decode_google_token(token, db)
            if user:
                return user
                
        # Try API Key
        if api_key:
            logger.info("Validating API key")
            user, permissions = verify_api_key(api_key, db)
            if user:
                return user, permissions
    except APIKeyError as api_key_error:
        raise api_key_error
    except JWTExpiredSignatureError as jwt_error:
        raise jwt_error
    except Exception as e:
        logger.info("Authentication Error", error=e)
        raise HTTPException(status_code=401, detail="Invalid or missing authentication")



def get_user_with_user_id(user_id, db):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user



async def creat_user_account(userinfo, db):
    """"""
    google_id = userinfo["sub"]
    try:
        user = db.query(User).filter(User.id == google_id).first()
        if not user:
            user = User(id=google_id, email=userinfo.get('email'), name=userinfo.get('name'))
            db.add(user)
            db.commit()
            db.refresh(user)

            await create_user_wallet(db, user.id)
    except Exception as e:
        raise AccountSetUpError(status_code=400, detail="Error creating user and wallet account")


async def create_user_wallet(db, user_id):
    wallet = Wallet(user_id=user_id, wallet_number=generate_unique_wallet_number())
    db.add(wallet)
    db.commit()


def generate_unique_wallet_number():
    return str(uuid4().int)[:10]
  


async def create_user_api_key(user_id, req, db, old_key=None) -> APIKeyResponse:
    expires_at = parse_expiry(req.expiry)
    key = "sk_live_" + secrets.token_hex(16)
    key_params = {}
    if old_key:
       key_params = old_key 
    else:
        key_params = req
    api_key = APIKey(user_id=user_id, key=key, name=key_params.name, permissions=key_params.permissions, expires_at=expires_at)
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return APIKeyResponse(api_key=key, expires_at=expires_at.isoformat())


def parse_expiry(expiry: str) -> datetime:
    """Convert expiry time in format like 1H, 2H 3D to datetime object"""
    now = datetime.utcnow()
    expiry_length = int(expiry[0])  
    expire_time = expiry[1].upper()

    if expire_time == "H":
        return now + timedelta(hours=1*expiry_length)
    elif expire_time == "D":
        return now + timedelta(days=1*expiry_length)
    elif expire_time == "M":
        return now + timedelta(days=30*expiry_length)
    elif expire_time == "Y":
        return now + timedelta(days=365*expiry_length)
    
    raise ValueError("Invalid expiry")




def get_current_user(
    db: Session = Depends(get_db),
    jwt_credentials: HTTPAuthorizationCredentials = Security(jwt_scheme),
):
    """
    Retrieve the current JWT authenticated user from the request.
    """
    try:
        logger.info("Getting current user")
        if not jwt_credentials:
            raise HTTPException(status_code=401, detail="Unathorized requires jwt Auth")
        if jwt_credentials:
            token = jwt_credentials.credentials
            user = decode_google_token(token, db)
            if user:
                return user
    except JWTExpiredSignatureError as jwt_error:
        raise jwt_error
    except HTTPException as auth_error:
        raise auth_error
    except Exception as e:
        logger.info("Authentication Error", error=e)
        raise HTTPException(status_code=401, detail="Invalid or missing authentication")
