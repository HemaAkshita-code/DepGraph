import os
from urllib import response

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

    vulnerability_details = get_vunerability_dependency_details(task_id)
    context_prompt = vulnerability_details

    response = client.responses.parse(
        model="openai/gpt-oss-20b",
        input=[
            {
                "role": "system",
                "content": vulnerability_summary
            },
            {
                "role": "user",
                "content": context_prompt 
            }
        ],
        text_format=StudentContext
    )

    return response.output_parsed

def generate_remediation_plan(task_id, request: Request):

    vulnerability_details = get_vunerability_dependency_details(task_id)
    project_repo_link_and_project_sha = get_project_repo_link_and_sha(task_id)

    context_prompt = "".join([vulnerability_details, project_repo_link_and_project_sha])

    response = client.responses.parse(
        model="openai/gpt-oss-20b",
        input=[
            {
                "role": "system",
                "content": remediation_plan
            },
            {
                "role": "user",
                "content": context_prompt
            }
        ],
        text_format=StudentContext
    )

    return response.output_parsed

def analyse_vulnerabilty_impacts(task_id, request :Request):

     vulnerability_details = get_vunerability_dependency_details(task_id)
     project_repo_link_and_project_sha = get_project_repo_link_and_sha(task_id)

     context_prompt = "".join([vulnerability_details, project_repo_link_and_project_sha])
    

     response = client.responses.parse(
        model="openai/gpt-oss-20b",
        input=[
            {
                "role": "system",
                "content": impact_analysis
            },
            {
                "role": "user",
                "content": context_prompt
            }
        ],
        text_format=StudentContext
    )

     return response.output_parsed

