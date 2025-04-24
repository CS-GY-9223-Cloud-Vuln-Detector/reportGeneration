from fastapi import FastAPI
from supabase import create_client, Client
from typing import List
from collections import defaultdict
from dotenv import load_dotenv
import os
from fastapi.middleware.cors import CORSMiddleware
import httpx
import asyncio

async def get_llama_fix_suggestion_async(vuln_type, file_name, line_from, description):
    prompt = (
        f"The file `{file_name}` has a vulnerability: '{vuln_type}' "
        f"on line {line_from}. {description} "
        f"Suggest a secure fix."
    )
    async with httpx.AsyncClient(timeout=120) as client:
        try:
            response = await client.post(
                "http://localhost:8001/v1/chat/completions",
                json={
                    "model": "meta-llama/Llama-3.2-3B-Instruct",
                    "messages": [{"role": "user", "content": prompt}]
                }
            )
            return response.json()["choices"][0]["message"]["content"].strip()
        except Exception as e:
            return f"⚠️ Error generating suggestion: {str(e)}"

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/report/{project_id}")
async def generate_vulnerability_report(project_id: str):
    # Fetch files in the project
    files_response = supabase.table("files").select("*").eq("project_id", project_id).execute()
    files_data = files_response.data

    if not files_data:
        return {"message": "No files found for this project", "project_id": project_id}

    result = {
        "project_id": project_id,
        "summary": {
            "total_files_scanned": len(files_data),
            "total_vulnerabilities": 0,
            "vulnerability_counts": {}
        },
        "files": []
    }

    vuln_count_by_type = defaultdict(int)

    for file in files_data:
        file_entry = {
            "file_name": file["file_name"],
            "file_type": file["file_type"],
            "md5": file["md5"],
            "loc": file["loc"],
            "file_url": file["file_url"],
            "vulnerabilities": []
        }

        vuln_query = (
            supabase.table("vulnerabilities")
            .select("*, vuln_types(name, description)")
            .eq("file_id", file["id"])
            .execute()
        )

        vulnerabilities = vuln_query.data
        result["summary"]["total_vulnerabilities"] += len(vulnerabilities)

        # for vuln in vulnerabilities:
        #     vuln_type = vuln["vuln_types"]["name"]
        #     vuln_count_by_type[vuln_type] += 1
        #     suggestion = get_llama_fix_suggestion(
        #         vuln_type,
        #         file["file_name"],
        #         vuln["line_from"],
        #         vuln["vuln_types"]["description"]
        #     )
        #     file_entry["vulnerabilities"].append({
        #         "type": vuln_type,
        #         "description": vuln["vuln_types"]["description"],
        #         "line_from": vuln["line_from"],
        #         "line_to": vuln["line_to"],
        #         "created_at": vuln["created_at"],
        #         "suggestion": suggestion
        #     })

        # Collect all async suggestion calls first
        suggestion_tasks = [
            get_llama_fix_suggestion_async(
                vuln["vuln_types"]["name"],
                file["file_name"],
                vuln["line_from"],
                vuln["vuln_types"]["description"]
            )
            for vuln in vulnerabilities
        ]

        suggestions = await asyncio.gather(*suggestion_tasks)

        for vuln, suggestion in zip(vulnerabilities, suggestions):
            vuln_type = vuln["vuln_types"]["name"]
            vuln_count_by_type[vuln_type] += 1

            file_entry["vulnerabilities"].append({
                "type": vuln_type,
                "description": vuln["vuln_types"]["description"],
                "line_from": vuln["line_from"],
                "line_to": vuln["line_to"],
                "created_at": vuln["created_at"],
                "suggestion": suggestion
            })

        result["files"].append(file_entry)

    result["summary"]["vulnerability_counts"] = dict(vuln_count_by_type)

    return result
