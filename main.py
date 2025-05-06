from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from dotenv import load_dotenv
import os, httpx, asyncio
from typing import Optional

# Load configuration
dotenv_path = os.getenv("DOTENV_PATH", None)
if dotenv_path:
    load_dotenv(dotenv_path)
else:
    load_dotenv()

SUPABASE_URL      = os.getenv("SUPABASE_URL")
SUPABASE_KEY      = os.getenv("SUPABASE_KEY")
VLLM_URL          = os.getenv("VLLM_URL", "http://localhost:8001/v1/chat/completions")
VLLM_MODEL        = os.getenv("VLLM_MODEL", "meta-llama/Llama-3.2-3B-Instruct")

if not (SUPABASE_URL and SUPABASE_KEY):
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")

# Initialize FastAPI and Supabase
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="."), name="static")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.get("/", include_in_schema=False)
async def serve_index():
    return FileResponse("index.html")

async def fetch_suggestion(prompt: str) -> Optional[str]:
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                VLLM_URL,
                json={"model": VLLM_MODEL, "messages": [{"role": "user", "content": prompt}]}
            )
            resp.raise_for_status()
            j = resp.json()
            return j["choices"][0]["message"]["content"].strip()
    except Exception:
        return None

@app.get("/report/{project_id}/{scan_id}")
async def report_scan(project_id: str, scan_id: str):
    # Verify the scan belongs to the project
    scan_resp = (
        supabase
        .table("scans")
        .select("project_id")
        .eq("id", scan_id)
        .single()
        .execute()
    )
    if not scan_resp.data or scan_resp.data.get("project_id") != project_id:
        raise HTTPException(status_code=404, detail="Scan not found for this project")

    # Fetch vulnerabilities + file metadata
    vuln_resp = (
        supabase
        .table("vulnerabilities")
        .select(
            "id,scan_id,file_id,line_from,line_to,code,cwe_id,vuln_description,"
            "files(file_name,file_type,md5,loc,file_url)"
        )
        .eq("scan_id", scan_id)
        .execute()
    )
    vulns = vuln_resp.data or []

    # Pre-load generic_fixes for all referenced cwe_ids
    cwe_ids = list({int(v.get("cwe_id")) for v in vulns if v.get("cwe_id")})
    cwe_map = {}
    if cwe_ids:
        cwe_resp = (
            supabase
            .table("cwe")
            .select("id,generic_fix")
            .in_("id", cwe_ids)
            .execute()
        )
        for row in cwe_resp.data or []:
            cwe_map[row["id"]] = row.get("generic_fix")

    result = {
        "project_id": project_id,
        "scan_id": scan_id,
        "summary": {
            "total_vulnerabilities": len(vulns),
            "unique_files": len({v["file_id"] for v in vulns})
        },
        "vulnerabilities": []
    }

    for v in vulns:
        file = v.get("files") or {}
        generic_fix = None
        try:
            cid = int(v.get("cwe_id"))
            generic_fix = cwe_map.get(cid)
        except (TypeError, ValueError):
            pass

        prompt = (
            f"File `{file.get('file_name')}` has a vulnerability on lines "
            f"{v['line_from']}-{v['line_to']}.\n"
            f"Code:\n{v['code']}\n\n"
            "Suggest a secure fix in one concise paragraph."
        )
        suggestion = await fetch_suggestion(prompt) or generic_fix or \
                     "LLM couldn't generate a suggestion for this error"

        result["vulnerabilities"].append({
            "file_name": file.get("file_name"),
            "file_type": file.get("file_type"),
            "loc": file.get("loc"),
            "file_url": file.get("file_url"),
            "line_from": v["line_from"],
            "line_to": v["line_to"],
            "code": v["code"],
	    "vuln_description": v.get("vuln_description"),
            "suggestion": suggestion
        })

    return result

from jinja2 import Environment, FileSystemLoader
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO

# Point Jinja at your project root (or wherever you store templates)
jinja_env = Environment(loader=FileSystemLoader(searchpath="templates"))

def render_report_html(report: dict) -> str:
    tpl = jinja_env.get_template("report.html")   # see below
    return tpl.render(report=report)
@app.get("/report/{project_id}/{scan_id}/pdf")
async def report_pdf(project_id: str, scan_id: str):
    report = await report_scan(project_id, scan_id)
    buf = BytesIO()
    doc = SimpleDocTemplate(buf)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"Project {project_id} / Scan {scan_id}", styles["Title"]))
    story.append(Paragraph(f"Total vulns: {report['summary']['total_vulnerabilities']}", styles["Normal"]))
    story.append(Paragraph(f"Files affected: {report['summary']['unique_files']}", styles["Normal"]))
    story.append(Spacer(1, 12))

    for v in report["vulnerabilities"]:
        story.append(Paragraph(f"{v['file_name']} (lines {v['line_from']}–{v['line_to']})", styles["Heading2"]))
        story.append(Paragraph(v["vuln_description"], styles["Normal"]))
        story.append(Paragraph(f"<pre>{v['code']}</pre>", styles["Code"]))
        story.append(Paragraph(f"Suggestion: {v['suggestion']}", styles["Italic"]))
        story.append(Spacer(1, 12))

    doc.build(story)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition":f'attachment; filename="report.pdf"'})
