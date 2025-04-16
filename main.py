from fastapi import FastAPI
from supabase import create_client, Client
from typing import List
from collections import defaultdict
from dotenv import load_dotenv
import os
from fastapi.middleware.cors import CORSMiddleware


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
def generate_vulnerability_report(project_id: str):
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

        for vuln in vulnerabilities:
            vuln_type = vuln["vuln_types"]["name"]
            vuln_count_by_type[vuln_type] += 1
            file_entry["vulnerabilities"].append({
                "type": vuln_type,
                "description": vuln["vuln_types"]["description"],
                "line_from": vuln["line_from"],
                "line_to": vuln["line_to"],
                "created_at": vuln["created_at"]
            })

        result["files"].append(file_entry)

    result["summary"]["vulnerability_counts"] = dict(vuln_count_by_type)

    return result
