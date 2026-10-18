
from fastapi import FastAPI, HTTPException
from app import database
from pydantic import BaseModel
from app.models import CreateTaskRequest
from app.models import SubmitTaskRequest
from app.models import LoginRequest
from app.models import SignupRequest
from pwdlib import PasswordHash

app = FastAPI()

@app.get("/")
def home():
    return("hey citizens!")

@app.post("/add_task")
def add_task(data: CreateTaskRequest):
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT deadline_hours
            FROM remediation_policies
            WHERE policy_id = :policy_id
              AND is_active = 'Y'
            """,
            {"policy_id": data.policy_id}
        )

        policy = cursor.fetchone()

        if policy is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid or inactive remediation policy"
            )

        cursor.execute(
            """
            INSERT INTO fix_tasks (
                project_id, vuln_id, created_by, policy_id,
                status, due_at, priority_reason,
                created_at, updated_at
            )
            VALUES (
                :project_id, :vuln_id, :created_by, :policy_id,
                'OPEN',
                SYSTIMESTAMP +
                    NUMTODSINTERVAL(:deadline_hours, 'HOUR'),
                :priority_reason,
                SYSTIMESTAMP, SYSTIMESTAMP
            )
            """,
            {
                "project_id": data.project_id,
                "vuln_id": data.vuln_id,
                "created_by": data.created_by,
                "policy_id": data.policy_id,
                "deadline_hours": policy[0],
                "priority_reason": data.priority_reason
            }
        )

        connection.commit()
        return {"message": "Task created successfully"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

@app.put("/assign_task/{task_id}/{team_id}")
def assign_task(task_id: int, team_id: int):
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        # Lock the task row and read its current state.
        cursor.execute(
            """
            SELECT status, team_id
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

        current_status, old_team_id = task
        new_status = "IN_PROGRESS"

        # Apply the central state-machine rule.
        validate_transition(current_status, new_status)

        # Assign the team and change the status together.
        cursor.execute(
            """
            UPDATE fix_tasks
            SET team_id = :team_id,
                status = :new_status,
                updated_at = SYSTIMESTAMP
            WHERE task_id = :task_id
            """,
            {
                "team_id": team_id,
                "new_status": new_status,
                "task_id": task_id
            }
        )

        # Record the change in the same transaction.
        cursor.execute(
            """
            INSERT INTO history_log (
                task_id,
                actor_user_id,
                action,
                old_values,
                new_values,
                created_at
            )
            VALUES (
                :task_id,
                NULL,
                'TASK_ASSIGNED',
                :old_values,
                :new_values,
                SYSTIMESTAMP
            )
            """,
            {
                "task_id": task_id,
                "old_values": (
                    f"team_id={old_team_id}; status={current_status}"
                ),
                "new_values": (
                    f"team_id={team_id}; status={new_status}"
                )
            }
        )

        connection.commit()

        return {
            "message": "Task assigned successfully",
            "status": new_status
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

@app.get("/view_teams")
def view_teams():
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

@app.post("/add_team/{team_id}/{team_name}")
def add_team(team_id: int, team_name: str):
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO teams (team_id, team_name)
            VALUES (:team_id, :team_name)
            """,
            {
                "team_id": team_id,
                "team_name": team_name
            }
        )

        connection.commit()
        return {"message": "Team added successfully"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

@app.get("/view_team_members/{team_id}")
def view_team_members(team_id: int):
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
    membership_role: str
):
    membership_role = membership_role.upper()

    if membership_role not in {
        "TEAM_LEAD", "CONTRIBUTOR", "REVIEWER"
    }:
        raise HTTPException(
            status_code=400,
            detail="Invalid membership role"
        )

    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO team_members (
                team_id, user_id, membership_role, joined_at
            )
            VALUES (
                :team_id, :user_id, :membership_role, SYSDATE
            )
            """,
            {
                "team_id": team_id,
                "user_id": user_id,
                "membership_role": membership_role
            }
        )

        connection.commit()
        return {"message": "Team member added successfully"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()

@app.get("/view_tasks")
def view_tasks():
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT task_id, project_id, vuln_id, team_id,
                   assigned_to, status, due_at
            FROM fix_tasks
            ORDER BY created_at DESC
            """
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
def view_pending_tasks():
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT task_id, project_id, vuln_id, team_id,
                   assigned_to, status, due_at
            FROM fix_tasks
            WHERE status = 'IN_REVIEW'
            ORDER BY created_at DESC
            """
        )

        rows = cursor.fetchall()
        columns = [
            description[0].lower()
            for description in cursor.description
        ]

        return {
            "Tasks awaiting review": [
                dict(zip(columns, row))
                for row in rows
            ]
        }

    finally:
        cursor.close()
        connection.close()


@app.get("/view_open_tasks")
def view_open_tasks():
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
def view_task_by_id(task_id: int):
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT *
            FROM fix_tasks
            WHERE task_id = :task_id
            """,
            {"task_id": task_id}
        )

        row = cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Task not found"
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

password_hash = PasswordHash.recommended()

@app.post("/login")
def login(data: LoginRequest):
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT password
            FROM users
            WHERE userid = :userid
            """,
            {"userid": data.userid}
        )

        result = cursor.fetchone()

        if result is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid user ID or password"
            )

        stored_hash = result[0]

        if not password_hash.verify(data.password, stored_hash):
            raise HTTPException(
                status_code=401,
                detail="Invalid user ID or password"
            )

        return {"message": "Login successful"}

    finally:
        cursor.close()
        connection.close()
    

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