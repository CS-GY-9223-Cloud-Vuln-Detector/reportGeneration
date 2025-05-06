#!/usr/bin/env python3
"""
generate_generic_fixes_vllm.py

Fetch CWEs with NULL generic_fix, query a local vLLM server sequentially,
and update only successful responses back to Supabase.

Requirements:
  - A `.env` file with SUPABASE_URL and SUPABASE_KEY
  - A running local vLLM instance on port 8001
  - Python packages: supabase, python-dotenv, httpx

Usage:
  source .venv/bin/activate
  pip install supabase python-dotenv httpx
  python generate_generic_fixes_vllm.py
"""
import os
import time
import httpx
from supabase import create_client, Client
from dotenv import load_dotenv

# Load configuration
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
VLLM_URL     = os.getenv("VLLM_URL", "http://localhost:8001/v1/chat/completions")
MODEL        = os.getenv("VLLM_MODEL", "meta-llama/Llama-3.2-3B-Instruct")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Helper to call local vLLM

def get_fix_vllm(name: str, desc: str) -> tuple[bool, str | None]:
    prompt = (
        f"Issue type: {name}.\n"
        f"Description: {desc}.\n\n"
        "Suggest a generic secure fix."
    )
    try:
        resp = httpx.post(
            VLLM_URL,
            json={
                "model": MODEL,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["choices"][0]["message"]["content"].strip()
        return True, text
    except Exception as e:
        print(f"   ✗ LLM error for CWE '{name}': {e}")
        return False, None


def main():
    # Fetch CWEs with no generic_fix
    resp = (
        supabase
        .table("cwe")
        .select("id,name,description")
        .is_("generic_fix", None)
        .execute()
    )
    rows = resp.data or []
    total = len(rows)
    print(f"Found {total} CWEs with NULL generic_fix.")

    for idx, row in enumerate(rows, start=1):
        cwe_id = row["id"]
        name   = row.get("name", "")
        desc   = row.get("description", "")

        print(f"[{idx}/{total}] CWE {cwe_id} → querying vLLM…", end=" ")
        success, fix = get_fix_vllm(name, desc)
        if success and fix:
            print("OK")
            # Update only on success
            try:
                supabase.table("cwe") \
                    .update({"generic_fix": fix}) \
                    .eq("id", cwe_id) \
                    .execute()
                print(f"   ✓ Updated CWE {cwe_id}")
            except Exception as e:
                print(f"   ✗ Supabase update failed: {e}")
        else:
            print("Skipped due to LLM error")

        # Small pause to avoid flooding the server
        time.sleep(0.1)

if __name__ == "__main__":
    main()
