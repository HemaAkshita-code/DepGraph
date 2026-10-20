
import json
import os

from fastapi import FastAPI, HTTPException, Request
from . import database
from pydantic import BaseModel
from .models import AssignTaskRequest, CreateTaskRequest, SubmitTaskRequest, LoginRequest, SignupRequest, CreateTeamRequest
from .models import CreateUserRequest, ChangePasswordRequest, GetRemediationPlanRequest
from . import agent, services
from starlette.middleware.sessions import SessionMiddleware
from pwdlib import PasswordHash
import json
import oracledb

app = FastAPI()

@app.post("/remediation-plan")
def get_remediation_plan( data: GetRemediationPlanRequest, request: Request):
    user = services.get_current_user(request)
    vulnerability_summary = agent.vulnerability_summary(data.task_id, request)
    impact_analysis = agent.analyse_vulnerabilty_impacts(data.task_id, request)
    remediation_plan = agent.remediation_plan(data.task_id, request)
    return {
        "message": "Remediation plan generated successfully",
        "vulnerability_summary": vulnerability_summary,
        "impact_analysis": impact_analysis,
        "remediation_plan": remediation_plan
    }



@app.post("/admin/users", status_code=201)
def create_user(
    data: CreateUserRequest,
    request: Request
):
    admin = services.require_admin(request)

    role = data.role.upper()

    if role not in {"ADMIN", "USER"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid role"
        )

    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT 1
            FROM users
            WHERE userid = :userid OR email = :email
            """,
            {
                "userid": data.userid,
                "email": str(data.email)
            }
        )

        if cursor.fetchone() is not None:
            raise HTTPException(
                status_code=409,
                detail="Account already exists. Please log in."
            )

        hashed_password = password_hash.hash(
            data.temporary_password
        )

        cursor.execute(
            """
            INSERT INTO users (
                userid, email, password, role, is_active
            )
            VALUES (
                :userid, :email, :password, :role, 'Y'
            )
            """,
            {
                "userid": data.userid,
                "email": str(data.email),
                "password": hashed_password,
                "role": role
            }
        )

        connection.commit()

        return {
            "message": "Account created successfully",
            "userid": data.userid
        }

    except HTTPException:
        connection.rollback()
        raise

    except Exception as exc:
        connection.rollback()

        # Oracle unique-constraint violation.
        if "ORA-00001" in str(exc):
            raise HTTPException(
                status_code=409,
                detail="Account already exists. Please log in."
            ) from exc

        raise

    finally:
        cursor.close()
        connection.close()

app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET"],
    session_cookie="depgraph_session",
    max_age=60 * 60 * 8,  # 8 hours
    same_site="lax",
    https_only=False,  # Local HTTP development only
)

password_hash = PasswordHash.recommended()

@app.get("/")
def home():
    return("hey citizens!")

@app.post("/add_team", status_code=201)
def add_team(data: CreateTeamRequest, request: Request):
    services.require_admin(request)

    team_name = data.team_name.strip()

    if not team_name:
        raise HTTPException(
            status_code=400,
            detail="Team name cannot be empty"
        )

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
            {
                "team_name": team_name,
                "new_team_id": new_team_id
            }
        )

        team_id = new_team_id.getvalue()[0]
        connection.commit()

        return {
            "message": "Team created successfully",
            "team_id": team_id
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()




@app.post("/add_task", status_code=201)
def add_task(data: CreateTaskRequest, request: Request):
    admin = services.require_admin(request)
    connection = database.get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        # 1. Find the active remediation policy for this priority.
        cursor.execute("""
            SELECT policy_id, deadline_hours
            FROM remediation_policies
            WHERE priority = :priority
              AND is_active = 'Y'
        """, {"priority": data.priority})

        policy = cursor.fetchone()

        if policy is None:
            raise HTTPException(
                status_code=409,
                detail="No active remediation policy exists for this priority"
            )

        policy_id, deadline_hours = policy

        # 2. Create the remediation task.
        new_id = cursor.var(int)

        cursor.execute("""
            INSERT INTO fix_tasks (
                project_id, vuln_id, created_by, policy_id,
                priority_reason, status, due_at
            )
            VALUES (
                :project_id, :vuln_id, :created_by, :policy_id,
                :priority_reason, 'OPEN',
                SYSTIMESTAMP + NUMTODSINTERVAL(:hours, 'HOUR')
            )
            RETURNING task_id INTO :new_id
        """, {
            "project_id": data.project_id,
            "vuln_id": data.vuln_id,
            "created_by": admin["userid"],
            "policy_id": policy_id,
            "priority_reason": data.priority_reason,
            "hours": deadline_hours,
            "new_id": new_id
        })

        task_id = new_id.getvalue()[0]

        # 3. Record the task creation in the audit history.
        cursor.execute("""
            INSERT INTO history_log (
                task_id, actor_user_id, action,
                old_values, new_values, created_at
            )
            VALUES (
                :task_id, :actor_user_id, 'TASK_CREATED',
                NULL, :new_values, SYSTIMESTAMP
            )
        """, {
            "task_id": task_id,
            "actor_user_id": admin["userid"],
            "new_values": json.dumps({
                "project_id": data.project_id,
                "vuln_id": data.vuln_id,
                "priority": data.priority,
                "policy_id": policy_id,
                "deadline_hours": deadline_hours,
                "priority_reason": data.priority_reason
            })
        })

        # 4. Save both the task and its history together.
        connection.commit()

        return {
            "message": "Remediation task created successfully",
            "task_id": task_id
        }

    except oracledb.IntegrityError as exc:
        connection.rollback()

        error = exc.args[0]

        # ORA-02291: a referenced project or vulnerability does not exist.
        if error.code == 2291:
            raise HTTPException(
                status_code=404,
                detail="Project or vulnerability not found"
            ) from exc

        # Let other database integrity errors propagate for now.
        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        if cursor is not None:
            cursor.close()

        connection.close()



@app.post("/assign_task")
def assign_task(data: AssignTaskRequest, request: Request):
    admin = services.require_admin(request)

    connection = database.get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        # 1. Find the task and lock its row while we update it.
        cursor.execute("""
            SELECT status, team_id
            FROM fix_tasks
            WHERE task_id = :task_id
            FOR UPDATE
        """, {"task_id": data.task_id})

        task = cursor.fetchone()

        if task is None:
            raise HTTPException(
                status_code=404,
                detail="Task not found"
            )

        old_status, old_team_id = task

        # 2. Check whether this status change is allowed.
        validate_transition(old_status, "IN_PROGRESS")

        # 3. Verify that the target team exists.
        cursor.execute("""
            SELECT 1
            FROM teams
            WHERE team_id = :team_id
        """, {"team_id": data.team_id})

        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=404,
                detail="Team not found"
            )

        # 4. Assign the task to the team and start the work.
        cursor.execute("""
            UPDATE fix_tasks
            SET team_id = :team_id,
                status = 'IN_PROGRESS',
                updated_at = SYSTIMESTAMP
            WHERE task_id = :task_id
        """, {
            "team_id": data.team_id,
            "task_id": data.task_id
        })

        # 5. Record the change in the audit history.
        cursor.execute("""
            INSERT INTO history_log (
                task_id, actor_user_id, action,
                old_values, new_values, created_at
            )
            VALUES (
                :task_id, :actor_user_id, 'TEAM_ASSIGNED',
                :old_values, :new_values, SYSTIMESTAMP
            )
        """, {
            "task_id": data.task_id,
            "actor_user_id": admin["userid"],
            "old_values": json.dumps({
                "team_id": old_team_id,
                "status": old_status
            }),
            "new_values": json.dumps({
                "team_id": data.team_id,
                "status": "IN_PROGRESS"
            })
        })

        # 6. Save the task update and audit record together.
        connection.commit()

        return {
            "message": "Task assigned successfully",
            "task_id": data.task_id,
            "team_id": data.team_id,
            "status": "IN_PROGRESS"
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        if cursor is not None:
            cursor.close()

        connection.close()


@app.get("/view_teams")
def view_teams(request: Request):
    admin = services.require_admin(request)
    connection = database.get_connection()
    cursor = connection.cursor()
    
    try:
        cursor.execute(
            "SELECT team_id, team_name FROM teams ORDER BY team_name"
        )

        rows = cursor.fetchall()

        return {
            "Teams": [
                {"team_id": row[0], "team_name": row[1]}
                for row in rows
            ]
        }

    finally:
        cursor.close()
        connection.close()

@app.get("/view_team_members/{team_id}")
def view_team_members(team_id: int, request: Request):
    admin = services.require_admin(request)
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                tm.team_id,
                tm.user_id,
                u.username,
                tm.membership_role,
                tm.joined_at
            FROM team_members tm
            JOIN users u ON tm.user_id = u.user_id
            WHERE tm.team_id = :team_id
            ORDER BY tm.joined_at
            """,
            {"team_id": team_id}
        )

        rows = cursor.fetchall()

        return {
            "Team members": [
                {
                    "team_id": row[0],
                    "user_id": row[1],
                    "username": row[2],
                    "membership_role": row[3],
                    "joined_at": row[4].isoformat() if row[4] else None
                }
                for row in rows
            ]
        }

    finally:
        cursor.close()
        connection.close()


@app.post("/add_team_member/{team_id}/{user_id}/{membership_role}")
def add_team_member(
    team_id: int,
    user_id: int,
    membership_role: str,
    request: Request
):
    # Only Admins can add team members for now.
    services.require_admin(request)

    # Validate the membership role, not the user's account role.
    membership_role = membership_role.upper()

    allowed_membership_roles = {
        "TEAM_LEAD",
        "CONTRIBUTOR",
        "REVIEWER"
    }

    if membership_role not in allowed_membership_roles:
        raise HTTPException(
            status_code=400,
            detail="Invalid membership role"
        )

    connection = database.get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        # Verify that the team exists.
        cursor.execute("""
            SELECT 1
            FROM teams
            WHERE team_id = :team_id
        """, {"team_id": team_id})

        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=404,
                detail="Team not found"
            )

        # Verify that the user exists and is active.
        cursor.execute("""
            SELECT 1
            FROM users
            WHERE userid = :user_id
              AND is_active = 'Y'
        """, {"user_id": user_id})

        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=404,
                detail="Active user not found"
            )

        # Add the user to the team.
        cursor.execute("""
            INSERT INTO team_members (
                team_id,
                user_id,
                membership_role,
                joined_at
            )
            VALUES (
                :team_id,
                :user_id,
                :membership_role,
                SYSDATE
            )
        """, {
            "team_id": team_id,
            "user_id": user_id,
            "membership_role": membership_role
        })

        connection.commit()

        return {
            "message": "Team member added successfully",
            "team_id": team_id,
            "user_id": user_id,
            "membership_role": membership_role
        }

    except HTTPException:
        connection.rollback()
        raise

    except oracledb.IntegrityError as exc:
        connection.rollback()
        error = exc.args[0]

        # ORA-00001: a unique constraint was violated.
        if error.code == 1:
            raise HTTPException(
                status_code=409,
                detail="This user may already belong to the team"
            ) from exc

        # ORA-02291: a referenced parent record does not exist.
        if error.code == 2291:
            raise HTTPException(
                status_code=404,
                detail="Team or user not found"
            ) from exc

        raise

    except Exception:
        connection.rollback()
        raise

    finally:
        if cursor is not None:
            cursor.close()

        connection.close()


@app.get("/view_tasks")
def view_tasks(request: Request):
    user = services.get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        if user["role"] == "ADMIN":
            cursor.execute(
                """
                SELECT task_id, project_id, vuln_id, team_id,
                       assigned_to, status, due_at
                FROM fix_tasks
                ORDER BY created_at DESC
                """
            )
        else:
            cursor.execute(
                """
                SELECT ft.task_id, ft.project_id, ft.vuln_id,
                       ft.team_id, ft.assigned_to,
                       ft.status, ft.due_at
                FROM fix_tasks ft
                WHERE EXISTS (
                    SELECT 1
                    FROM team_members tm
                    WHERE tm.team_id = ft.team_id
                      AND tm.user_id = :userid
                )
                ORDER BY ft.created_at DESC
                """,
                {"userid": user["userid"]}
            )

        rows = cursor.fetchall()
        columns = [
            description[0].lower()
            for description in cursor.description
        ]

        return {
            "Tasks": [
                dict(zip(columns, row))
                for row in rows
            ]
        }

    finally:
        cursor.close()
        connection.close()

@app.get("/view_pending_tasks")
def view_pending_tasks(request: Request):
    user = services.get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        if user["role"] == "ADMIN":
            # Admin can see pending tasks from every team.
            cursor.execute("""
                SELECT task_id, project_id, vuln_id, team_id,
                       assigned_to, status, due_at
                FROM fix_tasks
                WHERE status IN ('OPEN', 'IN_PROGRESS', 'IN_REVIEW',
                                 'CHANGES_REQUESTED')
                ORDER BY due_at ASC
            """)

        else:
            # Other users can see pending tasks only for their teams.
            cursor.execute("""
                SELECT ft.task_id, ft.project_id, ft.vuln_id,
                       ft.team_id, ft.assigned_to, ft.status, ft.due_at
                FROM fix_tasks ft
                WHERE ft.status IN (
                    'OPEN', 'IN_PROGRESS', 'IN_REVIEW',
                    'CHANGES_REQUESTED'
                )
                AND EXISTS (
                    SELECT 1
                    FROM team_members tm
                    WHERE tm.team_id = ft.team_id
                      AND tm.user_id = :userid
                )
                ORDER BY ft.due_at ASC
            """, {"userid": user["userid"]})

        rows = cursor.fetchall()
        columns = [column[0].lower() for column in cursor.description]

        return {
            "pending_tasks": [
                dict(zip(columns, row))
                for row in rows
            ]
        }

    finally:
        cursor.close()
        connection.close()

@app.get("/view_open_tasks")
def view_open_tasks(request: Request):
    admin = services.require_admin(request)
    connection = database.get_connection()
    cursor = connection.cursor()
    

    try:
        cursor.execute(
            """
            SELECT task_id, project_id, vuln_id, team_id,
                   assigned_to, status, due_at
            FROM fix_tasks
            WHERE status = 'OPEN'
            ORDER BY created_at DESC
            """
        )

        rows = cursor.fetchall()
        columns = [
            description[0].lower()
            for description in cursor.description
        ]

        return {
            "Open Tasks": [
                dict(zip(columns, row))
                for row in rows
            ]
        }

    finally:
        cursor.close()
        connection.close()

@app.get("/view_task_by_id/{task_id}")
def view_task_by_id(task_id: int, request: Request):
    user = services.get_current_user(request)
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        if user["role"] != "ADMIN":
            cursor.execute(
                """
                SELECT task_id, project_id, vuln_id, team_id,
                       assigned_to, status, due_at
                FROM fix_tasks ft
                WHERE ft.task_id = :task_id
                  AND EXISTS (
                      SELECT 1
                      FROM team_members tm
                      WHERE tm.team_id = ft.team_id
                        AND tm.user_id = :userid
                  )
                """,
                {"task_id": task_id, "userid": user["userid"]}
            )
        else:
            cursor.execute(
                """
                SELECT task_id, project_id, vuln_id, team_id,
                       assigned_to, status, due_at
                FROM fix_tasks
                WHERE task_id = :task_id
                """,
                {"task_id": task_id}
            )

        row = cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Task not found or you do not have access to it"
            )

        columns = [
            description[0].lower()
            for description in cursor.description
        ]

        return {"Task": dict(zip(columns, row))}

    finally:
        cursor.close()
        connection.close()

    

#user_id in session, so I can verify authorisation

#@app.get("/login")

@app.post("/submit_task/{task_id}")
def submit_task(task_id: int, data: SubmitTaskRequest):
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT status
            FROM fix_tasks
            WHERE task_id = :task_id
            FOR UPDATE
            """,
            {"task_id": task_id}
        )

        task = cursor.fetchone()

        if task is None:
            raise HTTPException(
                status_code=404,
                detail="Task not found"
            )

        old_status = task[0]
        new_status = "IN_REVIEW"

        validate_transition(old_status, new_status)

        cursor.execute(
            """
            INSERT INTO fix_submissions (
                task_id, submitted_by, commit_sha,
                pull_request_url, change_summary, submitted_at
            )
            VALUES (
                :task_id, :submitted_by, :commit_sha,
                :pull_request_url, :change_summary, SYSTIMESTAMP
            )
            """,
            {
                "task_id": task_id,
                "submitted_by": data.submitted_by,
                "commit_sha": data.commit_sha,
                "pull_request_url": data.pull_request_url,
                "change_summary": data.change_summary
            }
        )

        cursor.execute(
            """
            UPDATE fix_tasks
            SET status = 'IN_REVIEW',
                updated_at = SYSTIMESTAMP
            WHERE task_id = :task_id
            """,
            {"task_id": task_id}
        )

        cursor.execute(
            """
            INSERT INTO history_log (
                task_id, actor_user_id, action,
                old_values, new_values, created_at
            )
            VALUES (
                :task_id, NULL, 'SUBMITTED_FOR_REVIEW',
                :old_values, :new_values, SYSTIMESTAMP
            )
            """,
            {
                "task_id": task_id,
                "old_values": f"status={old_status}",
                "new_values": "status=IN_REVIEW"
            }
        )

        connection.commit()

        return {"message": "Task submitted for review"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@app.post("/login")
def login(data: LoginRequest, request: Request):
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT password, role, is_active
            FROM users
            WHERE userid = :userid
            """,
            {"userid": data.userid}
        )

        user = cursor.fetchone()

        if (
            user is None
            or user[2] != "Y"
            or not password_hash.verify(data.password, user[0])
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid user ID or password"
            )

        # Start a fresh session after successful authentication.
        request.session.clear()
        request.session["userid"] = data.userid

        return {
            "message": "Login successful",
            "role": user[1]
        }

    finally:
        cursor.close()
        connection.close()

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"message": "Logged out successfully"}
    

@app.post("/signup")
def signup(data: SignupRequest):
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        hashed_password = password_hash.hash(data.password)

        cursor.execute(
            """
            INSERT INTO users (userid, email, password)
            VALUES (:username, :email, :password)
            """,
            {
                "username": data.username,
                "email": data.email,
                "password": hashed_password
            }
        )

        connection.commit()

        return {"message": "User created successfully"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


ALLOWED_TRANSITIONS = {
    "OPEN": {"IN_PROGRESS", "CANCELLED"},
    "IN_PROGRESS": {"IN_REVIEW", "CANCELLED"},
    "IN_REVIEW": {"RESOLVED", "CHANGES_REQUESTED"},
    "CHANGES_REQUESTED": {"IN_PROGRESS", "CANCELLED"},
    "RESOLVED": set(),
    "CANCELLED": set(),
}


def validate_transition(current_status: str, new_status: str):
    allowed = ALLOWED_TRANSITIONS.get(current_status, set())

    if new_status not in allowed:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Invalid task transition: "
                f"{current_status} -> {new_status}"
            )
        )