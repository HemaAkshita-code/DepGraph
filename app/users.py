from typing import Literal, Optional

import oracledb
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app import database
from app.auth import (
    generate_temporary_password,
    get_current_user,
    password_hash,
    require_admin,
)

router = APIRouter()

SystemRole = Literal["ADMIN", "SECURITY_ANALYST", "DEVELOPER", "AUDITOR"]
Designation = Literal[
    "SENIOR_DEVELOPER", "DEVELOPER", "INTERN",
    "SECURITY_ENGINEER", "AUDITOR", "MANAGER",
]
TeamRole = Literal["DEVELOPER", "REVIEWER", "TESTER"]


class CreateUserRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=100)
    email: str = Field(max_length=150, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    system_role: SystemRole
    designation: Designation


class UpdateUserRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=100)
    system_role: SystemRole
    designation: Designation


class CreateTeamRequest(BaseModel):
    team_name: str = Field(min_length=1, max_length=100)


class AddMemberRequest(BaseModel):
    user_id: int
    team_role: TeamRole = "DEVELOPER"


class SetLeaderRequest(BaseModel):
    user_id: Optional[int] = None


def _raise_db_error(exc: oracledb.DatabaseError):
    message = str(exc)
    if "ORA-00001" in message:
        raise HTTPException(status_code=409, detail="This record already exists") from exc
    if "ORA-02291" in message:
        raise HTTPException(status_code=404, detail="A referenced record does not exist") from exc
    if "ORA-02290" in message:
        raise HTTPException(status_code=400, detail="A value is not allowed") from exc
    raise exc


def _rows_as_dicts(cursor) -> list:
    columns = [column[0].lower() for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


# ------------------------------------------------------------------ Users

@router.post("/users", status_code=201, tags=["Users"])
def create_user(data: CreateUserRequest, request: Request):
    require_admin(request)

    temporary_password = generate_temporary_password()

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        new_user_id = cursor.var(int)
        cursor.execute(
            """
            INSERT INTO users (
                full_name, email, password_hash, must_change_password,
                system_role, designation
            )
            VALUES (
                :full_name, :email, :password_hash, 'Y',
                :system_role, :designation
            )
            RETURNING user_id INTO :new_user_id
            """,
            {
                "full_name": data.full_name.strip(),
                "email": data.email.strip().lower(),
                "password_hash": password_hash.hash(temporary_password),
                "system_role": data.system_role,
                "designation": data.designation,
                "new_user_id": new_user_id,
            },
        )
        connection.commit()

        return {
            "message": "User created. Share the temporary password with them securely",
            "user_id": new_user_id.getvalue()[0],
            "temporary_password": temporary_password,
        }

    except HTTPException:
        connection.rollback()
        raise

    except oracledb.DatabaseError as exc:
        connection.rollback()
        if "ORA-00001" in str(exc):
            raise HTTPException(status_code=409, detail="A user with this email already exists") from exc
        _raise_db_error(exc)

    finally:
        cursor.close()
        connection.close()


@router.get("/users", tags=["Users"])
def list_users(request: Request, include_inactive: bool = False):
    require_admin(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT user_id, full_name, email, system_role, designation,
                   is_active, joined_on, left_on
            FROM users
            WHERE :include_inactive = 1 OR is_active = 'Y'
            ORDER BY full_name
            """,
            {"include_inactive": 1 if include_inactive else 0},
        )
        return {"users": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.get("/users/{user_id}", tags=["Users"])
def get_user(user_id: int, request: Request):
    current = get_current_user(request)

    if current["role"] != "ADMIN" and current["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="You can only view your own profile")

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT user_id, full_name, email, system_role, designation,
                   is_active, joined_on, left_on
            FROM users
            WHERE user_id = :user_id
            """,
            {"user_id": user_id},
        )
        rows = _rows_as_dicts(cursor)
        if not rows:
            raise HTTPException(status_code=404, detail="User not found")
        return {"user": rows[0]}

    finally:
        cursor.close()
        connection.close()


@router.put("/users/{user_id}", tags=["Users"])
def update_user(user_id: int, data: UpdateUserRequest, request: Request):
    admin = require_admin(request)

    if admin["user_id"] == user_id and data.system_role != "ADMIN":
        raise HTTPException(status_code=400, detail="You cannot remove your own admin role")

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE users
            SET full_name = :full_name,
                system_role = :system_role,
                designation = :designation
            WHERE user_id = :user_id
            """,
            {
                "full_name": data.full_name.strip(),
                "system_role": data.system_role,
                "designation": data.designation,
                "user_id": user_id,
            },
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")

        connection.commit()
        return {"message": "User updated successfully"}

    except HTTPException:
        connection.rollback()
        raise

    except oracledb.DatabaseError as exc:
        connection.rollback()
        _raise_db_error(exc)

    finally:
        cursor.close()
        connection.close()


@router.post("/users/{user_id}/deactivate", tags=["Users"])
def deactivate_user(user_id: int, request: Request):
    """
    One transaction: mark the user as left, remove them as leader of any team,
    and end their sessions. Their history and memberships are kept.
    """
    admin = require_admin(request)

    if admin["user_id"] == user_id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT is_active FROM users WHERE user_id = :user_id FOR UPDATE",
            {"user_id": user_id},
        )
        row = cursor.fetchone()

        if row is None:
            raise HTTPException(status_code=404, detail="User not found")
        if row[0] == "N":
            raise HTTPException(status_code=409, detail="User is already inactive")

        cursor.execute(
            "SELECT team_id, team_name FROM teams WHERE leader_user_id = :user_id",
            {"user_id": user_id},
        )
        teams_without_leader = _rows_as_dicts(cursor)

        cursor.execute(
            "UPDATE teams SET leader_user_id = NULL WHERE leader_user_id = :user_id",
            {"user_id": user_id},
        )
        cursor.execute(
            """
            UPDATE users
            SET is_active = 'N',
                left_on = SYSDATE
            WHERE user_id = :user_id
            """,
            {"user_id": user_id},
        )
        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id = :user_id",
            {"user_id": user_id},
        )

        connection.commit()
        return {
            "message": "User deactivated",
            "teams_needing_new_leader": teams_without_leader,
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.post("/users/{user_id}/activate", tags=["Users"])
def activate_user(user_id: int, request: Request):
    require_admin(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE users
            SET is_active = 'Y',
                left_on = NULL
            WHERE user_id = :user_id
              AND is_active = 'N'
            """,
            {"user_id": user_id},
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Inactive user not found")

        connection.commit()
        return {"message": "User reactivated"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


# ------------------------------------------------------------------ Teams

@router.post("/teams", status_code=201, tags=["Teams"])
def create_team(data: CreateTeamRequest, request: Request):
    require_admin(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        new_team_id = cursor.var(int)
        cursor.execute(
            """
            INSERT INTO teams (team_name)
            VALUES (:team_name)
            RETURNING team_id INTO :new_team_id
            """,
            {"team_name": data.team_name.strip(), "new_team_id": new_team_id},
        )
        connection.commit()

        return {
            "message": "Team created successfully",
            "team_id": new_team_id.getvalue()[0],
        }

    except oracledb.DatabaseError as exc:
        connection.rollback()
        if "ORA-00001" in str(exc):
            raise HTTPException(status_code=409, detail="A team with this name already exists") from exc
        _raise_db_error(exc)

    finally:
        cursor.close()
        connection.close()


@router.get("/teams", tags=["Teams"])
def list_teams(request: Request):
    get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT t.team_id, t.team_name, t.leader_user_id,
                   u.full_name AS leader_name,
                   (SELECT COUNT(*) FROM team_members tm
                    WHERE tm.team_id = t.team_id) AS member_count
            FROM teams t
            LEFT JOIN users u ON u.user_id = t.leader_user_id
            ORDER BY t.team_name
            """
        )
        return {"teams": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.get("/teams/{team_id}/members", tags=["Teams"])
def list_team_members(team_id: int, request: Request):
    current = get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        if current["role"] != "ADMIN":
            cursor.execute(
                """
                SELECT 1 FROM team_members
                WHERE team_id = :team_id AND user_id = :user_id
                """,
                {"team_id": team_id, "user_id": current["user_id"]},
            )
            if cursor.fetchone() is None:
                raise HTTPException(
                    status_code=403,
                    detail="You can only view members of your own teams",
                )

        cursor.execute(
            """
            SELECT tm.user_id, u.full_name, u.designation, tm.team_role,
                   tm.joined_on, u.is_active,
                   CASE WHEN t.leader_user_id = tm.user_id
                        THEN 'Y' ELSE 'N' END AS is_leader
            FROM team_members tm
            JOIN users u ON u.user_id = tm.user_id
            JOIN teams t ON t.team_id = tm.team_id
            WHERE tm.team_id = :team_id
            ORDER BY tm.joined_on
            """,
            {"team_id": team_id},
        )
        return {"team_id": team_id, "members": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.post("/teams/{team_id}/members", status_code=201, tags=["Teams"])
def add_team_member(team_id: int, data: AddMemberRequest, request: Request):
    require_admin(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT is_active FROM users WHERE user_id = :user_id",
            {"user_id": data.user_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="User not found")
        if row[0] != "Y":
            raise HTTPException(status_code=400, detail="Inactive users cannot join a team")

        cursor.execute(
            """
            INSERT INTO team_members (team_id, user_id, team_role)
            VALUES (:team_id, :user_id, :team_role)
            """,
            {"team_id": team_id, "user_id": data.user_id, "team_role": data.team_role},
        )
        connection.commit()
        return {"message": "Member added to team"}

    except HTTPException:
        connection.rollback()
        raise

    except oracledb.DatabaseError as exc:
        connection.rollback()
        message = str(exc)
        if "ORA-00001" in message:
            raise HTTPException(status_code=409, detail="User is already in this team") from exc
        if "ORA-02291" in message:
            raise HTTPException(status_code=404, detail="Team not found") from exc
        _raise_db_error(exc)

    finally:
        cursor.close()
        connection.close()


@router.delete("/teams/{team_id}/members/{user_id}", tags=["Teams"])
def remove_team_member(team_id: int, user_id: int, request: Request):
    require_admin(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE teams SET leader_user_id = NULL
            WHERE team_id = :team_id AND leader_user_id = :user_id
            """,
            {"team_id": team_id, "user_id": user_id},
        )
        was_leader = cursor.rowcount == 1

        cursor.execute(
            "DELETE FROM team_members WHERE team_id = :team_id AND user_id = :user_id",
            {"team_id": team_id, "user_id": user_id},
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="This user is not in this team")

        connection.commit()
        return {
            "message": "Member removed from team",
            "team_needs_new_leader": was_leader,
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.put("/teams/{team_id}/leader", tags=["Teams"])
def set_team_leader(team_id: int, data: SetLeaderRequest, request: Request):
    """Set or change the team leader. The new leader must already be an active member."""
    require_admin(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        if data.user_id is not None:
            cursor.execute(
                "SELECT is_active FROM users WHERE user_id = :user_id",
                {"user_id": data.user_id},
            )
            row = cursor.fetchone()
            if row is None or row[0] != "Y":
                raise HTTPException(status_code=400, detail="Leader must be an active user")

        cursor.execute(
            "UPDATE teams SET leader_user_id = :user_id WHERE team_id = :team_id",
            {"user_id": data.user_id, "team_id": team_id},
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Team not found")

        connection.commit()
        return {"message": "Team leader updated"}

    except HTTPException:
        connection.rollback()
        raise

    except oracledb.DatabaseError as exc:
        connection.rollback()
        if "ORA-02291" in str(exc):
            raise HTTPException(
                status_code=400,
                detail="The new leader must be a member of this team",
            ) from exc
        _raise_db_error(exc)

    finally:
        cursor.close()
        connection.close()
