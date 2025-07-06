from fastapi import FastAPI
from pydantic import BaseModel, EmailStr
import dns.resolver
import requests
import asyncio
from functools import lru_cache

app = FastAPI(title="SmartMailGuard API")

# Disposable domain sources
DISPOSABLE_LIST_URLS = [
    "https://raw.githubusercontent.com/tompec/disposable-email-domains/main/index.json",
    "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt",
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/refs/heads/main/disposable_email_blocklist.conf"
]

UPDATE_INTERVAL_SECONDS = 12 * 60 * 60  # 12 hours

# Fallback TLD heuristic
suspicious_tlds = {"xyz", "top", "tk", "lol", "click", "gq", "cf"}

# Global in-memory set
disposable_domains = set()


# Load domains from the sources
def update_disposable_list() -> set:
    disposable_set = set()
    for url in DISPOSABLE_LIST_URLS:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                if url.endswith(".json"):
                    data = response.json()
                    disposable_set.update(map(str.lower, data))
                else:
                    lines = response.text.splitlines()
                    disposable_set.update(line.strip().lower() for line in lines if line.strip())
                print(f"[Loader] Fetched domains from: {url}")
            else:
                print(f"[Loader] Failed to fetch from {url}: {response.status_code}")
        except Exception as e:
            print(f"[Loader] Error fetching from {url}: {e}")
    return disposable_set


# Initialize at startup
def load_disposable_domains():
    global disposable_domains
    disposable_domains = update_disposable_list()


# Background refresh scheduler
async def refresh_disposable_list_loop():
    global disposable_domains
    while True:
        print("[Scheduler] Updating disposable domain list...")
        updated_set = update_disposable_list()
        if updated_set:
            disposable_domains = updated_set
        await asyncio.sleep(UPDATE_INTERVAL_SECONDS)


@app.on_event("startup")
async def startup_event():
    load_disposable_domains()
    asyncio.create_task(refresh_disposable_list_loop())


# Models
class EmailRequest(BaseModel):
    email: EmailStr

class BulkEmailRequest(BaseModel):
    emails: list[EmailStr]


# Utility logic
def interpret_score(score: int) -> str:
    if score >= 90:
        return "High trust: valid format, likely safe"
    elif score >= 70:
        return "Medium trust: may be valid but needs caution"
    elif score >= 40:
        return "Low trust: suspicious or disposable"
    else:
        return "Very low trust: likely fake or invalid"

def is_disposable(email: str) -> bool:
    domain = email.split("@")[-1].lower()
    return domain in disposable_domains or is_suspicious(email)

def is_suspicious(email: str) -> bool:
    domain = email.split("@")[-1].lower()
    tld = domain.split(".")[-1]
    return tld in suspicious_tlds

@lru_cache(maxsize=1000)
def has_mx_record(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except Exception:
        return False

def validate_email(email: str) -> dict:
    domain = email.split("@")[-1].lower()
    disposable = is_disposable(email)
    mx_found = has_mx_record(domain)
    score = 100
    if disposable:
        score -= 50
    if not mx_found:
        score -= 30
    return {
        "email": email,
        "valid_format": True,
        "disposable": disposable,
        "mx_found": mx_found,
        "score": f"{max(score, 0)} ({interpret_score(score)})"
    }


# API Routes
@app.post("/validate")
async def validate_single_email(payload: EmailRequest):
    return validate_email(payload.email)

@app.post("/bulk-validate")
async def validate_bulk_emails(payload: BulkEmailRequest):
    loop = asyncio.get_event_loop()
    results = await asyncio.gather(*[
        loop.run_in_executor(None, validate_email, email)
        for email in payload.emails
    ])
    return {"results": results}

@app.get("/health")
async def health_check():
    return {"status": "ok"}