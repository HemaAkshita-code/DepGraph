from pydantic import BaseModel, EmailStr, Field
from typing import Literal

class SubmitTaskRequest(BaseModel):
    submitted_by: int
    commit_sha: str
    pull_request_url: str
    change_summary: str
    
class CreateTaskRequest(BaseModel):
    project_id: int
    vuln_id: int
    priority: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    priority_reason: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str

class CreateTeamRequest(BaseModel):
    team_name: str = Field(min_length=1, max_length=100)


class CreateUserRequest(BaseModel):
    userid: str = Field(min_length=1, max_length=50)
    email: EmailStr
    temporary_password: str = Field(min_length=12)
    role: str = "USER"


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)

class AssignTaskRequest(BaseModel):
    task_id: int
    team_id: int

class GetRemediationPlanRequest(BaseModel):
    task_id: int