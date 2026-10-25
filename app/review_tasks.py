
from . import database, services
from fastapi import Request
from .models import SetReviewStatus

def view_review_tasks(request : Request):
    user = services.get_current_user(request)
    if not user:
        raise Exception("User not authenticated")

    connection = database.get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(""" select task_id, sub,mitted_by, commit_sha, base_sha, pull_request_url, change_summary from fix_submissions join fix_tasks on fix_submission.task_id = fix_tasks.tasks_id when fix_tasks.reviewer_user_id = :userid """, {"userid" : user["userid"]})
        result = cursor.fetchone();

        return 
        
    except Exception as e:
        raise e

    finally:
        cursor.close()
        connection.close()


def review_submission(data: SetReviewStatus ,request : Request):
    user = services.get_current_user(request)
    if not user:
        raise Exception("User not authenticated")

    connection = database.get_db_connection()
    cursor = connection.cursor()
    try:
        if(data.status == 'CHANGES_REQUESTED'):
            cursor.execute("insert into ") # insert feedback
            # else, just insert status
    except Exception as e:
        raise e
    
    finally:
        cursor.close()
        connection.close()