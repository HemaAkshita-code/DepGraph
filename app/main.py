
from fastapi import FastAPI 
from app import database
from pydantic import BaseModel
from pwdlib import PasswordHash

app = FastAPI()

@app.get("/")
def home():
    return("hey citizens!")

@app.post("/add_task/{task_id}/{vulnerability_id}")
def add_task(task: dict):
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "insert into fix_tasks (task_id, vulnerability_id, status) values (:task_id, :vulnerability_id, 'open')"
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()  
        connection.close()

@app.post("/assign_task/{task_id}/{vulnerability_id}/{team_id}")
def add_task(task: dict):
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "insert into remediation_tasks (team_id, status) values (:team_id, 'pending') where task_id = :task_id and vulnerability_id = :vulnerability_id"
        )
        connection.commit()
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
        cursor.execute("SELECT * FROM teams")
        result = cursor.fetchall()
        return {"Teams": result}
    except Exception as e:
        return {"Error occurred": str(e)}
    finally:
        cursor.close()
        connection.close()

@app.post("/add_team/{team_id}/{team_name}")
def add_team(team: dict):
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "insert into teams (team_id, team_name) values (:team_id, :team_name)"
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()  
        connection.close()

@app.get("/view_team_members/{team_id}")
def view_team_members(team_id: str):
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT team_members.*, users.username FROM team_members join users ON team_members.user_id = users.user_id WHERE team_members.team_id = :team_id", {"team_id": team_id})
        result = cursor.fetchall()
        return {"Team members": result}
    except Exception as e:
        return {"Error occurred": str(e)}
    finally:
        cursor.close()
        connection.close()

@app.post("/add_team_member/{team_id}/{user_id}/{membership_role}/{joined_at}")
def add_team_member(team_member: dict):
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "insert into team_members (team_id, user_id, membership_role, joined_at) values (:team_id, :user_id, :membership_role, :joined_at)"
        )
        connection.commit()
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
        cursor.execute("SELECT * FROM remediation_tasks")
        result = cursor.fetchall()
        return {"Tasks": result}
    except Exception as e:
        return {"Error occurred": str(e)}
    finally:
        cursor.close()
        connection.close()

@app.get("/view_pending_tasks")
def view_pending_tasks():
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM remediation_tasks WHERE status = 'pending'")
        result = cursor.fetchall()
        return {"Pending Tasks": result}
    except Exception as e:
        return {"Error occurred": str(e)}
    finally:
        cursor.close()
        connection.close()  

@app.get("/view_open_tasks")
def view_open_tasks():
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM remediation_tasks WHERE status = 'open'")
        result = cursor.fetchall()
        return {"Open Tasks": result}
    except Exception as e:
        return {"Error occurred": str(e)}
    finally:
        cursor.close()
        connection.close()

@app.get("/view_task_by_id/{task_id}")
def view_task_by_id(task_id):
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM remediation_tasks WHERE task_id = :task_id")
        result = cursor.fetchall()
        return {"Task": result}
    except Exception as e:
        return {"Error occurred": str(e)}
    finally:
        cursor.close()
        connection.close()

#user_id in cookie, so I can verify authorisation

#@app.get("/login")

@app.post("/submit_task/{task_id}/{team_id}")
def submit_task(task: dict):
    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "UPDATE remediation_tasks SET status = 'submitted' WHERE task_id = :task_id and team_id = :team_id"
        )

        cursor.execute(
                "INSERT INTO history_log (task_id, action) VALUES (:id, :action)"
                )
        
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()  
        connection.close()


class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(data: LoginRequest):
    username = data.userid
    password = data.password

    password_hash = PasswordHash.recommended()

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT password from users WHERE userid = :userid")

        result = cursor.fetchone()
        if password_hash.verify(result, password):
            return {"message": "Login successful"}
        else:
            return {"message": "Invalid username or password"}
    except Exception as e:
        return {"Error occurred": str(e)}
    finally:
        connection.close()
        cursor.close()

@app.get("/signup")
def signup():
    userid = data.userid
    password = data.password

    password_hash = PasswordHash.recommended()

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        hashed_password = password_hash.hash(password)
        cursor.execute("INSERT INTO users (userid, password) VALUES (:userid, hashed_paassword)")
        connection.commit()
        return {"message": "User created successfully"}

    
    except Exception as e:
        connection.rollback()
        return {"Error occurred": str(e)}
    finally:
        connection.close()
        cursor.close()

    
