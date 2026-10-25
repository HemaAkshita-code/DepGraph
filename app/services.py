from fastapi import Request, HTTPException
from . import auth

def get_current_user(request: Request):
    user = auth.get_current_user(request)

    return {
        **user,
        "userid": user["user_id"]
    }

def require_admin(request: Request):
    user = get_current_user(request)

    if user["role"] != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Admin permission required"
        )

    return user