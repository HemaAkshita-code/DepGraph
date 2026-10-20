
from fastapi import Request

from .services import get_current_user

from . import database


def get_vunerability_dependency_details(task_id, request: Request):
    user = get_current_user(request)
    if not user:
        raise Exception("User not authenticated")
    
    connection = database.get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("select task_id, project_id, vulnerability_id from fix_tasks where task_id = :task_id and user_id =:user_id ", {"task_id" : task_id, "user_id" : user["userid"]}) 
       #match vulnerability_id with dependency_id and get those details as well
        result = cursor.fetchone()  
        if result is None:
            raise Exception("Task not found or user not authorized")

        return "".join(str(item) for item in result)#.join(dependency_id, package_name, version, fixed_version, severity, description, references)
    except Exception as e:
        raise e 
    
    finally:
        cursor.close()
        connection.close()


def get_project_repo_link_and_sha(task_id, request: Request):
    user = get_current_user(request)
    if not user:
        raise Exception("User not authenticated")
    
    connection = database.get_db_connection()
    cursor = connection.cursor()

    user_id = user["userid"]

    try:
        cursor.execute("select pull_request_url, commit_sha, base_sha from fix_submissions where task_id = :task_id and exists(select 1 from fix_tasks where fix_tasks.task_id = :task_id and fix_tasks.team_id = (select team_members.team_id from users inner join team_members on users.user_id = team_members.user_id where users.user_id = :user_id))", {"task_id" : task_id, "user_id" : user_id})
        result = cursor.fetchone()
        if result is None:
            cursor.execute("select projects.repo_url, projects.scanned_commit_sha from projects join fix_tasks on projects.project_id = fix_tasks.project_id where fix_tasks.task_id = :task_id and fix_tasks.team_id = (select team_members.team_id from users inner join team_members on users.user_id = team_members.user_id where users.user_id = :user_id)", {"task_id" : task_id, "user_id" : user_id})
            result = cursor.fetchone()
            if result is None:
                raise Exception("Project not found or user not authorized")

        return "".join(str(item) for item in result)
    except Exception as e:
        raise e 
    
    finally:
        cursor.close()
        connection.close()