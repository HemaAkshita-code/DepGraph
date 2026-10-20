
from fastapi import Request, HTTPException
from . import database

def get_current_user(request: Request):
    userid = request.session.get("userid")

    if userid is None:
        raise HTTPException(
            status_code=401,
            detail="Please log in first"
        )

    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT userid, role, is_active
            FROM users
            WHERE userid = :userid
            """,
            {"userid": userid}
        )

        user = cursor.fetchone()

        if user is None or user[2] != "Y":
            request.session.clear()
            raise HTTPException(
                status_code=401,
                detail="Account is inactive or no longer exists"
            )

        return {
            "userid": user[0],
            "role": user[1]
        }

    finally:
        cursor.close()
        connection.close()


def require_admin(request: Request):
    user = get_current_user(request)

    if user["role"] != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Admin permission required"
        )

    return user
