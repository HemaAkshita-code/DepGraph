
from fastapi import Request

from . import database, services
from .models import SubmitTaskRequest
from .vulnerability_scan import execute_scan

def submit_task(data: SubmitTaskRequest, request: Request):
    user = services.get_current_user(request)
    if not user:
        raise Exception("User not authenticated")
    
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        # Verify task authorization
        cursor.execute(
            """
            SELECT 1 FROM fix_tasks 
            WHERE task_id = :task_id 
              AND team_id = (
                  SELECT team_members.team_id 
                  FROM users 
                  INNER JOIN team_members ON users.user_id = team_members.user_id 
                  WHERE users.user_id = :user_id
              )
            """,
            {"task_id": data.task_id, "user_id": user["userid"]}
        )
      
        result = cursor.fetchone()
        if result is None:
            raise Exception("Task not found or user not authorized")
        
        # Insert submission record
        cursor.execute(
        """
        INSERT INTO fix_submissions (
            task_id, 
            submitted_by, 
            commit_sha, 
            base_sha, 
            pull_request_url, 
            change_summary, 
            submitted_at
        )
        VALUES (
            :task_id, 
            :submitted_by, 
            :commit_sha, 
            (
                SELECT p.scanned_commit_sha 
                FROM fix_tasks ft 
                JOIN projects p ON ft.project_id = p.project_id 
                WHERE ft.task_id = :task_id
            ), 
            :pull_request_url, 
            :change_summary,
            SYSTIMESTAMP
        )
        """,
        {
            "task_id": data.task_id,
            "submitted_by": user["userid"],
            "commit_sha": data.commit_sha,
            "pull_request_url": data.pull_request_url,
            "change_summary": data.change_summary
        }
            )

        # Run vulnerability scan
        # vuln_count = execute_scan()

        # if vuln_count == 0:
        cursor.execute(
            """
            UPDATE fix_tasks
            SET status = 'IN REVIEW'
            WHERE task_id = :task_id
            """,
            {"task_id": data.task_id}
        )
        response_message = {"message": "Task submitted successfully"}
        # else:
            # cursor.execute(
            #     """
            #     UPDATE fix_tasks
            #     SET status = 'REJECTED'
            #     WHERE task_id = :task_id
            #     """,
            #     {"task_id": data.task_id}
            # )
            # response_message = {"message": str(vuln_count) + " - vulnerabilities still exist in your code"}

        # Commit transaction for both paths before returning
        connection.commit()
        return response_message
        
    except Exception as e:
        connection.rollback()
        raise e
    finally:
        cursor.close()
        connection.close()


def get_submitted_tasks(task_id: str, request: Request):
    user = services.get_current_user(request)
    if not user:
        raise Exception("User not authenticated")
    
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        # Admins can view submissions freely; regular users can view submissions for tasks matching their access
        if user["role"] == "ADMIN":
            cursor.execute(
                """
                SELECT task_id, submitted_by, commit_sha, pull_request_url, change_summary
                FROM fix_submissions 
                WHERE task_id = :task_id
                """,
                {"task_id": task_id}
            )
        else:
            cursor.execute(
                """
                SELECT fs.task_id, fs.submitted_by, fs.commit_sha, fs.pull_request_url, fs.change_summary
                FROM fix_submissions fs
                JOIN fix_tasks ft ON fs.task_id = ft.task_id
                WHERE fs.task_id = :task_id 
                  AND fs.submitted_by = :user_id 
                  AND ft.status = 'RESOLVED'
                """,
                {"task_id": task_id, "user_id": user["userid"]}
            )
            
        results = cursor.fetchall()
        return [
            {
                "task_id": row[0],
                "submitted_by": row[1],
                "commit_sha": row[2],
                "pull_request_url": row[3],
                "change_summary": row[4]
            }
            for row in results
        ]
    except Exception as e:
        raise e
    finally:
        cursor.close()
        connection.close()