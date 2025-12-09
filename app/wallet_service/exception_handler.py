from fastapi import HTTPException



class JWTExpiredSignatureError(HTTPException):
    pass


class APIKeyError(HTTPException):
    pass


class AccountSetUpError(HTTPException):
    pass

class TransferError(HTTPException):
    pass