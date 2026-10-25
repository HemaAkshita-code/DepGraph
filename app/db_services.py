
from fastapi import Request, HTTPException

from .services import get_current_user
from . import database

def get_vunerability_dependency_details(task_id: int, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="User not authenticated")
    
    connection = database.get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT 
                ft.task_id,
                ft.project_id,
                p.project_name,
                v.vuln_id,
                v.advisory_code,
                v.title AS vulnerability_title,
                v.severity_score,
                pad.package_name,
                pad.version_text
            FROM fix_tasks ft
            JOIN projects p ON ft.project_id = p.project_id
            JOIN vulnerabilities v ON ft.vuln_id = v.vuln_id
            LEFT JOIN project_exposures pe ON ft.project_id = pe.project_id AND ft.vuln_id = pe.vuln_id
            LEFT JOIN project_all_dependencies pad ON pe.project_id = pad.project_id AND pe.version_id = pad.version_id
            WHERE ft.task_id = :task_id 
              AND ft.team_id = (
                  SELECT team_id 
                  FROM team_members 
                  WHERE user_id = :user_id
              )
            """, 
            {
                "task_id": task_id, 
                "user_id": user["userid"]
            }
        )
        
        result = cursor.fetchone()  
        if result is None:
            raise HTTPException(
                status_code=404, 
                detail="Task not found or user not authorized"
            )

        return {
            "task_id": result[0],
            "project_id": result[1],
            "project_name": result[2],
            "vuln_id": result[3],
            "advisory_code": result[4],
            "vulnerability_title": result[5],
            "severity_score": result[6],
            "package_name": result[7],
            "version": result[8]
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise
    finally:
        cursor.close()
        connection.close()

def get_project_repo_link_and_sha(task_id, request: Request):
    user = get_current_user(request)
    if not user:
        raise Exception("User not authenticated")
    
    connection = database.get_connection()
    cursor = connection.cursor()

    user_id = user["userid"]

    try:
        cursor.execute("select pull_request_url, commit_sha, base_sha from fix_submissions where task_id = :task_id and exists(select 1 from fix_tasks where fix_tasks.task_id = :task_id and fix_tasks.team_id = (select team_id from team_members where user_id = :user_id))", {"task_id" : task_id, "user_id" : user_id})
        result = cursor.fetchone()
        if result is None:
            cursor.execute("select projects.repo_url, projects.scanned_commit_sha from projects join fix_tasks on projects.project_id = fix_tasks.project_id where fix_tasks.task_id = :task_id and fix_tasks.team_id = (select team_members.team_id from users inner join team_members on users.user_id = team_members.user_id where users.user_id = :user_id)", {"task_id" : task_id, "user_id" : user_id})
            result = cursor.fetchone()
            if result is None:
                raise Exception("Project not found or user not authorized")

        return "".join(str(item) for item in result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise 
    
    finally:
        cursor.close()
        connection.close()