
from fastapi import Request

from app import database, services
from app.models import SubmitTaskRequest


def submit_task(request : Request, data: SubmitTaskRequest):
    user = services.get_current_user(request)
    if not user:
        raise Exception("User not authenticated")
    
    connection = database.get_db_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            select 1 from fix_tasks where task_id = :task_id and team_id = (select team_members.team_id from users inner join team_members on users.user_id = team_members.user_id where users.user_id = :user_id)
            """,{"task_id": data.task_id,"user_id": user["userid"]})
      
        result = cursor.fetchone()
        if result is None:
            raise Exception("Task not found or user not authorized")
        
        cursor.execute(
            """
            INSERT INTO fix_submissions (task_id, submitted_by, commit_sha, pull_request_url, change_summary)
            VALUES (:task_id, :submitted_by, :commit_sha, :pull_request_url, :change_summary) 
            """,
            {
                "task_id": data.task_id,
                "submitted_by": user["userid"],
                "commit_sha": data.commit_sha,
                "pull_request_url": data.pull_request_url,
                "change_summary": data.change_summary
            }
        )

        # update dependencies in db and run vulnerability scan, if detected status = reject, if not detected, status = in review

        cursor.execute(
            """
            UPDATE fix_tasks
            SET status = 'IN REVIEW'
            WHERE task_id = :task_id
            """,
            {"task_id": data.task_id}
        )

        connection.commit()
        return {"message": "Task submitted successfully"}
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
    
    connection = database.get_db_connection()
    cursor = connection.cursor()

    try:
        if user["role"] != "ADMIN":
            cursor.execute(
                        """
                        SELECT task_id, submitted_by, commit_sha, pull_request_url, change_summary
                        FROM fix_submissions where task_id = :task_id 
                        """,
                        {
                            "task_id": task_id
                        }
                    )
        else:
            cursor.execute(
                """
                SELECT task_id, submitted_by, commit_sha, pull_request_url, change_summary
                FROM fix_submissions
                WHERE submitted_by = :user_id
                """,
                {"user_id": user["userid"]}
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