
from . import database, services
from fastapi import Request, HTTPException

from .models import SetReviewStatus

def view_review_tasks(request: Request):
    user = services.get_current_user(request)
    if not user:
        raise Exception("User not authenticated")
    
    # DEBUG PRINT
    print(f"DEBUG USER SESSION: {user}, User ID: {user.get('userid') or user.get('user_id')}")

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT 
                fs.submission_id, 
                fs.task_id, 
                fs.submitted_by, 
                fs.commit_sha, 
                fs.base_sha, 
                fs.pull_request_url, 
                fs.change_summary 
            FROM fix_submissions fs
            JOIN fix_tasks ft ON fs.task_id = ft.task_id 
            WHERE ft.reviewer_user_id = :userid
            """, 
            {"userid": user.get("userid") or user.get("user_id")}
        )
        result = cursor.fetchall()
        print(f"DEBUG FETCHED ROWS: {len(result)}")
        
        return [
            {
                "submission_id": row[0],
                "task_id": row[1],
                "submitted_by": row[2],
                "commit_sha": row[3],
                "base_sha": row[4],
                "pull_request_url": row[5],
                "change_summary": row[6]
            }
            for row in result
        ]
    except Exception as e:
        raise e
    finally:
        cursor.close()
        connection.close()


def review_submission(request: Request, data: SetReviewStatus):
    user = services.get_current_user(request)

    if not user:
        raise HTTPException(status_code=401, detail="User not authenticated")

    connection = database.get_connection()
    cursor = connection.cursor()

    try:

        # Verify that this submission belongs to a task assigned
        # to the current user as reviewer.
        cursor.execute("""
            SELECT fs.task_id
            FROM fix_submissions fs
            JOIN fix_tasks ft
                ON fs.task_id = ft.task_id
            WHERE fs.submission_id = :submission_id
              AND ft.reviewer_user_id = :reviewer_user_id
        """, {
            "submission_id": data.submission_id,
            "reviewer_user_id": user["userid"]
        })

        result = cursor.fetchone()

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="Submission not found or you are not its reviewer"
            )

        task_id = result[0]

        print(f"DEBUG REVIEW FEEDBACK VALUE: '{data.changes_requested}'")
        

        cursor.execute("""
            INSERT INTO fix_reviews (
                submission_id,
                reviewer_user_id,
                decision,
                feedback,
                reviewed_at
            )
            VALUES (
                :submission_id,
                :reviewer_user_id,
                :decision,
                :feedback,
                SYSTIMESTAMP
            )
        """, {
            "submission_id": data.submission_id,
            "reviewer_user_id": user["userid"],
            "decision": data.status,
            "feedback": data.changes_requested
        })


        cursor.execute("""
            UPDATE fix_tasks
            SET status = :status
            WHERE task_id = :task_id
        """, {
            "status": data.status,
            "task_id": task_id
        })

        connection.commit()

        return {
            "message": "Review submitted successfully",
            "submission_id": data.submission_id,
            "status": data.status
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()
