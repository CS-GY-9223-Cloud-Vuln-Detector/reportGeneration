#!/usr/bin/env python3
"""
generate_generic_fixes_hf.py

Sequentially fetch CWEs with NULL generic_fix, call Hugging Face Chat Completions,
and update the DB on success (≤2 requests/sec with simple 503 retry logic).
"""
import os
import time
from supabase import create_client
from huggingface_hub import InferenceClient
from dotenv import load_dotenv

# 1) Load creds
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
HF_TOKEN     = os.getenv("HF_TOKEN")

if not (SUPABASE_URL and SUPABASE_KEY and HF_TOKEN):
    raise RuntimeError("Please set SUPABASE_URL, SUPABASE_KEY, and HF_TOKEN in .env")

# 2) Init clients
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
client   = InferenceClient(provider="novita",api_key=HF_TOKEN)

# 3) Fetch rows needing fixes
resp = (
    supabase
    .table("cwe")
    .select("id,name,description")
    .is_("generic_fix", None)
    .gte("id", 1)
    .lte("id", 500)
    .execute()
)
rows = resp.data or []
print(f"Found {len(rows)} CWEs to fix (generic_fix=NULL).")

# 4) Helper: Chat completion with 503 retry
def get_fix(prompt: str) -> str:
    for attempt in range(1, 4):
        try:
            completion = client.chat.completions.create(
                model="deepseek-ai/DeepSeek-V3-0324",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=512,
            )
            # `.message.content` is your generated text
            return completion.choices[0].message.content.strip()
        except Exception as e:
            if "503" in str(e) and attempt < 3:
                wait = 2 ** (attempt - 1)
                print(f"   ⚠️ 503, retry {attempt}/3 in {wait}s…")
                time.sleep(wait)
                continue
            # re‐raise on non‑503 or final failure
            raise

# 5) Main loop
for idx, r in enumerate(rows, start=1):
    cwe_id = r["id"]
    name   = r.get("name","[no name]")
    desc   = r.get("description","[no desc]")

    prompt = (
        f"Issue type: {name}.\n"
        f"Description: {desc}.\n\n"
        "Suggest a generic secure fix."
    )

    print(f"[{idx}/{len(rows)}] CWE {cwe_id} → querying HF…", end=" ")
    try:
        fix = get_fix(prompt)
        print("OK")

        # write back
        supabase.table("cwe") \
            .update({"generic_fix": fix}) \
            .eq("id", cwe_id) \
            .execute()
        print(f"   ✓ Updated CWE {cwe_id}")

    except Exception as e:
        print(f"ERROR: {e}")

    # throttle to ≤ 2 req/sec
    time.sleep(0.5)
