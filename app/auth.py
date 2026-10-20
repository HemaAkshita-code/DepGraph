import secrets

from fastapi import APIRouter, HTTPException, Request, Response
from pwdlib import PasswordHash
from pydantic import BaseModel, Field

from app import database

router = APIRouter(prefix="/auth", tags=["Authentication"])

password_hash = PasswordHash.recommended()

SESSION_COOKIE = "depgraph_session"
SESSION_HOURS = 8


class LoginRequest(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


def generate_temporary_password() -> str:
    return secrets.token_urlsafe(9)


def _load_session_user(request: Request) -> dict:
    """Return the logged-in user for the session cookie, or raise 401."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Please log in first")

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT u.user_id, u.full_name, u.email,
                   u.system_role, u.must_change_password
            FROM user_sessions s
            JOIN users u ON u.user_id = s.user_id
            WHERE s.session_token = :token
              AND s.expires_at > SYSDATE
              AND u.is_active = 'Y'
            """,
            {"token": token},
        )
        row = cursor.fetchone()
    finally:
        cursor.close()
        connection.close()

    if row is None:
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid. Please log in again",
        )

    return {
        "user_id": row[0],
        "full_name": row[1],
        "email": row[2],
        "role": row[3],
        "must_change_password": row[4] == "Y",
    }


def get_current_user(request: Request) -> dict:
    """
    Logged-in user for every protected endpoint.
    Returns {"user_id", "full_name", "email", "role", "must_change_password"}.
    Users holding a temporary password must change it before doing anything else.
    """
    user = _load_session_user(request)
    if user["must_change_password"]:
        raise HTTPException(
            status_code=403,
            detail="Please change your temporary password first",
        )
    return user


def require_role(*roles: str):
    def checker(request: Request) -> dict:
        user = get_current_user(request)
        if user["role"] not in roles:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission for this action",
            )
        return user

    return checker


require_admin = require_role("ADMIN")


@router.post("/login")
def login(data: LoginRequest, response: Response):
    email = data.email.strip().lower()

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT user_id, full_name, password_hash, is_active,
                   system_role, must_change_password
            FROM users
            WHERE email = :email
            """,
            {"email": email},
        )
        row = cursor.fetchone()

        if row is None or row[2] is None or not password_hash.verify(data.password, row[2]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        user_id, full_name, _, is_active, role, must_change = row

        if is_active != "Y":
            raise HTTPException(status_code=403, detail="This account has been deactivated")

        token = secrets.token_urlsafe(32)
        cursor.execute(
            """
            INSERT INTO user_sessions (session_token, user_id, expires_at)
            VALUES (:token, :user_id, SYSDATE + :hours / 24)
            """,
            {"token": token, "user_id": user_id, "hours": SESSION_HOURS},
        )
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_HOURS * 3600,
        httponly=True,
        samesite="lax",
    )

    return {
        "message": "Login successful",
        "user_id": user_id,
        "full_name": full_name,
        "role": role,
        "must_change_password": must_change == "Y",
    }


@router.post("/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)

    if token:
        connection = database.get_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                "DELETE FROM user_sessions WHERE session_token = :token",
                {"token": token},
            )
            connection.commit()
        finally:
            cursor.close()
            connection.close()

    response.delete_cookie(SESSION_COOKIE)
    return {"message": "Logged out"}


@router.get("/me")
def me(request: Request):
    return _load_session_user(request)


@router.post("/change-password")
def change_password(data: ChangePasswordRequest, request: Request):
    user = _load_session_user(request)
    current_token = request.cookies.get(SESSION_COOKIE)

    if data.new_password == data.current_password:
        raise HTTPException(
            status_code=400,
            detail="New password must be different from the current one",
        )

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT password_hash FROM users WHERE user_id = :user_id FOR UPDATE",
            {"user_id": user["user_id"]},
        )
        stored_hash = cursor.fetchone()[0]

        if not password_hash.verify(data.current_password, stored_hash):
            raise HTTPException(status_code=401, detail="Current password is incorrect")

        cursor.execute(
            """
            UPDATE users
            SET password_hash = :new_hash,
                must_change_password = 'N'
            WHERE user_id = :user_id
            """,
            {"new_hash": password_hash.hash(data.new_password), "user_id": user["user_id"]},
        )

        # Sign out every other device that was using the old password.
        cursor.execute(
            """
            DELETE FROM user_sessions
            WHERE user_id = :user_id
              AND session_token <> :token
            """,
            {"user_id": user["user_id"], "token": current_token},
        )

        connection.commit()
        return {"message": "Password changed successfully"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.post("/reset-password/{user_id}")
def reset_password(user_id: int, request: Request):
    """Admin sets a temporary password; the user must change it at next login."""
    require_admin(request)

    temporary_password = generate_temporary_password()

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE users
            SET password_hash = :new_hash,
                must_change_password = 'Y'
            WHERE user_id = :user_id
              AND is_active = 'Y'
            """,
            {"new_hash": password_hash.hash(temporary_password), "user_id": user_id},
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Active user not found")

        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id = :user_id",
            {"user_id": user_id},
        )

        connection.commit()
        return {
            "message": "Password reset. Share the temporary password with the user securely",
            "user_id": user_id,
            "temporary_password": temporary_password,
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

