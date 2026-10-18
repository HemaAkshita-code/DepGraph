from pydantic import BaseModel

class SubmitTaskRequest(BaseModel):
    submitted_by: int
    commit_sha: str
    pull_request_url: str
    change_summary: str
    
class CreateTaskRequest(BaseModel):
    project_id: int
    vuln_id: int
    created_by: int
    policy_id: int
    priority_reason: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str