


class CreateTaskRequest(BaseModel):
    project_id: int
    vuln_id: int
    created_by: int
    policy_id: int
    priority_reason: str