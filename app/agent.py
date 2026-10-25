import os
import json
from .services import get_current_user
from dotenv import load_dotenv
from fastapi import Request
from .prompts import vulnerability_summary, impact_analysis, remediation_plan  
from openai import OpenAI
from .db_services import get_vunerability_dependency_details, get_project_repo_link_and_sha

load_dotenv()

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1"
)

def generate_vulnerabilty_summary(task_id, request: Request):
    vulnerability_details = get_vunerability_dependency_details(task_id, request)
    # Include the word "json" in the prompt text to satisfy Groq's requirement
    context_prompt = json.dumps(vulnerability_details, indent=2) + "\n\nProvide the response as a JSON object."

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[
            {
                "role": "system",
                "content": vulnerability_summary
            },
            {
                "role": "user",
                "content": context_prompt
            }
        ],
        response_format={"type": "json_object"}
    )

    return response.choices[0].message.content

def generate_remediation_plan(task_id, request: Request):
    vulnerability_details = get_vunerability_dependency_details(task_id, request)
    project_repo_info = get_project_repo_link_and_sha(task_id, request)

    context_prompt = json.dumps({
        "vulnerability_details": vulnerability_details,
        "project_repo_info": project_repo_info
    }, indent=2) + "\n\nProvide the remediation plan as a JSON object."

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[
            {
                "role": "system",
                "content": remediation_plan
            },
            {
                "role": "user",
                "content": context_prompt
            }
        ],
        response_format={"type": "json_object"}
    )

    return response.choices[0].message.content

def analyse_vulnerabilty_impacts(task_id, request: Request):
    vulnerability_details = get_vunerability_dependency_details(task_id, request)
    project_repo_info = get_project_repo_link_and_sha(task_id, request)

    context_prompt = json.dumps({
        "vulnerability_details": vulnerability_details,
        "project_repo_info": project_repo_info
    }, indent=2) + "\n\nProvide the impact analysis as a JSON object."

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[
            {
                "role": "system",
                "content": impact_analysis
            },
            {
                "role": "user",
                "content": context_prompt
            }
        ],
        response_format={"type": "json_object"}
    )

    return response.choices[0].message.content