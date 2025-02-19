import asyncio
import base64
import hashlib
import logging
import re
import time
import uuid
from collections import deque
from functools import lru_cache
from typing import List, Optional

import email
from email import policy
from email.parser import BytesParser
from io import BytesIO

import numpy as np
from bs4 import BeautifulSoup
from fastapi import File, UploadFile, FastAPI, HTTPException, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.http.exceptions import UnexpectedResponse
from qdrant_client.http.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)
from sentence_transformers import SentenceTransformer
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest
)
from starlette.middleware.base import BaseHTTPMiddleware

# -------------------------------------------------------
# Logging Setup
# -------------------------------------------------------
LOG_LEVEL = "INFO"
LOG_FORMAT = "[%(asctime)s] %(levelname)s %(name)s - %(message)s"

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
logger = logging.getLogger("phishing_api")
logger.setLevel(logging.INFO)

uvicorn_logger = logging.getLogger("uvicorn")
uvicorn_logger.handlers = logger.handlers
uvicorn_logger.setLevel(logging.INFO)

uvicorn_error_logger = logging.getLogger("uvicorn.error")
uvicorn_error_logger.handlers = logger.handlers
uvicorn_error_logger.setLevel(logging.INFO)

uvicorn_access_logger = logging.getLogger("uvicorn.access")
uvicorn_access_logger.handlers = logger.handlers
uvicorn_access_logger.setLevel(logging.INFO)

# -------------------------------------------------------
# Prometheus Metrics & Middleware
# -------------------------------------------------------
REQUEST_LATENCY = Histogram(
    "request_duration_seconds",
    "Request duration in seconds",
    ["method", "path"]
)
REQUEST_COUNT = Counter(
    "request_count",
    "Number of requests by method, path and HTTP status",
    ["method", "path", "status_code"]
)

class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        request_duration = time.time() - start_time

        method = request.method
        path = request.url.path
        status_code = response.status_code

        REQUEST_LATENCY.labels(method=method, path=path).observe(request_duration)
        REQUEST_COUNT.labels(method=method, path=path, status_code=status_code).inc()

        return response

# -------------------------------------------------------
# FastAPI Initialization
# -------------------------------------------------------
app = FastAPI(title="Phishing Detection API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # or specify ["http://localhost:8000"] for stricter security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(PrometheusMiddleware)


# -------------------------------------------------------
# Qdrant Setup
# -------------------------------------------------------
client = QdrantClient("http://192.168.117.177:6333")
COLLECTION_NAME = "emails"

try:
    client.get_collection(collection_name=COLLECTION_NAME)
    logger.info(f"Collection '{COLLECTION_NAME}' already exists. Skipping creation.")
except UnexpectedResponse as e:
    if "Collection" in str(e) and "doesn" in str(e):
        logger.info(f"Collection '{COLLECTION_NAME}' does not exist. Creating it now...")
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=384, distance=Distance.COSINE)
        )
    else:
        raise

# -------------------------------------------------------
# Prepare background batch upsert
# -------------------------------------------------------
batch_queue = deque()
BATCH_SIZE = 10  # flush after 10 inserts
FLUSH_INTERVAL = 5  # or after 5s if not reached 10

model = SentenceTransformer("all-MiniLM-L6-v2")

@lru_cache(maxsize=1000)
def get_cached_embedding(text: str):
    return model.encode([text], show_progress_bar=False, convert_to_numpy=True).tolist()[0]
    #return model.encode([text], convert_to_numpy=True).tolist()[0]

async def batch_upsert():
    last_upsert_time = time.time()
    while True:
        elapsed = time.time() - last_upsert_time
        if len(batch_queue) >= BATCH_SIZE or (elapsed >= FLUSH_INTERVAL and len(batch_queue) > 0):
            points = []
            while batch_queue:
                points.append(batch_queue.popleft())
            client.upsert(COLLECTION_NAME, points)
            logger.info(f"✅ Upserted {len(points)} points to Qdrant.")
            last_upsert_time = time.time()
        await asyncio.sleep(1)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(batch_upsert())

# -------------------------------------------------------
# Pydantic Models
# -------------------------------------------------------
class EmailRequest(BaseModel):
    subject: str
    body: str
    sender: str
    reply_to: Optional[str] = None
    attachments: Optional[List[str]] = []
    type: Optional[str] = None
    customerId: Optional[str] = None

class AnalyzeResponse(BaseModel):
    phishing_score: int
    confidence_level: str
    closest_match: Optional[str]
    reasons: List[str]

# -------------------------------------------------------
# Utilities
# -------------------------------------------------------
def extract_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s\"<>]+", text)

def extract_eml_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition"))
            if ctype == "text/plain" and "attachment" not in cdisp:
                return part.get_payload(decode=True).decode(errors="replace")
            elif ctype == "text/html" and "attachment" not in cdisp:
                return BeautifulSoup(
                    part.get_payload(decode=True).decode(errors="replace"), "html.parser"
                ).get_text()
    return msg.get_payload(decode=True).decode(errors="replace")

def extract_email_features(email: EmailRequest):
    decoded_body = base64.b64decode(email.body)
    body_text = decoded_body[:200].decode(errors="replace")

    subject = email.subject
    sender = email.sender
    reply_to = email.reply_to or sender
    customer_id = email.customerId

    sender_domain = sender.split("@")[-1] if "@" in sender else "unknown"
    reply_to_domain = reply_to.split("@")[-1] if "@" in reply_to else "unknown"

    soup = BeautifulSoup(decoded_body, "html.parser")
    html_links = [a['href'] for a in soup.find_all('a', href=True)]
    text_links = extract_urls(decoded_body.decode(errors="replace"))
    merged_links = list(set(html_links + text_links))

    # For stable ID creation
    email_string = subject + body_text + "".join(merged_links) + sender_domain
    email_hash = hashlib.sha256(email_string.encode()).hexdigest()

    return {
        "subject": subject,
        "body_preview": body_text,
        "links": merged_links,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "attachments": email.attachments or [],
        "email_hash": email_hash,
        "customerId": customer_id,
    }

def store_email(email: EmailRequest, label: str) -> str:
    feats = extract_email_features(email)
    feats["label"] = label

    email_id_str = feats["email_hash"] + label
    email_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, email_id_str))

    vector_text = f"{feats['subject']} {feats['body_preview']} {' '.join(feats['links'])}"
    vector_embedding = get_cached_embedding(vector_text)

    point = PointStruct(id=email_id, vector=vector_embedding, payload=feats)
    batch_queue.append(point)

    logger.info(f"Queued {label} email: {feats['subject']} (ID={email_id}, custId={feats.get('customerId')})")
    return f"✅ Queued {label} email: {feats['subject']}"

def check_email_similarity(email_feats):
    vector_text = f"{email_feats['subject']} {email_feats['body_preview']} {' '.join(email_feats['links'])}"
    vector_embedding = get_cached_embedding(vector_text)

    filter_ = None
    if email_feats.get("customerId"):
        filter_ = Filter(
            must=[FieldCondition(key="customerId", match=MatchValue(value=email_feats["customerId"]))]
        )

    results = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vector_embedding,
        query_filter=filter_,
        limit=5
    )

    phishing_score = 0.0
    phishing_matches = []
    legit_matches = []
    max_similarity = 0.0
    closest_label = None

    for r in results:
        sim = r.score
        lbl = r.payload.get("label", "unknown")
        if sim > max_similarity:
            max_similarity = sim
            closest_label = lbl
        if lbl == "phishing":
            phishing_score += 50 * sim
            phishing_matches.append(r.payload.get("subject", "Unknown"))
        elif lbl == "legitimate":
            phishing_score -= 20 * sim
            legit_matches.append(r.payload.get("subject", "Unknown"))

    phishing_score = min(max(phishing_score, 0), 100)  # clamp 0-100
    phishing_score = int(phishing_score)

    reasons = []
    if phishing_matches:
        reasons.append(f"Similar to known phishing emails: {phishing_matches}")
    if not phishing_matches and not legit_matches:
        reasons.append("No strong phishing or legitimate indicators found.")

    return phishing_score, reasons, closest_label

# -------------------------------------------------------
# API Endpoints
# -------------------------------------------------------
@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/insert")
def insert_email(email: EmailRequest):
    logger.info(f"[/insert] subject={email.subject}")
    typ = email.type.lower() if email.type else ""
    if typ not in ["phishing", "legitimate"]:
        raise HTTPException(status_code=400, detail="Invalid email type.")
    msg = store_email(email, typ)
    return {"message": msg}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_email(email: EmailRequest):
    logger.info(f"[/analyze] subject={email.subject}")
    feats = extract_email_features(email)
    score, reasons, closest_label = check_email_similarity(feats)

    if score >= 70:
        conf = "High"
    elif score >= 40:
        conf = "Medium"
    else:
        conf = "Low"

    logger.info(f"Analyzed -> score={score}, conf={conf}, label={closest_label}")
    return AnalyzeResponse(
        phishing_score=score,
        confidence_level=conf,
        closest_match=closest_label,
        reasons=reasons
    )

@app.post("/report_false_positive")
def report_false_positive(email: EmailRequest):
    logger.info(f"[/report_false_positive] subject={email.subject}")
    feats = extract_email_features(email)

    vector_text = f"{feats['subject']} {feats['body_preview']} {' '.join(feats['links'])}"
    vec = get_cached_embedding(vector_text)

    filt = None
    if feats.get("customerId"):
        filt = Filter(must=[FieldCondition(key="customerId", match=MatchValue(value=feats["customerId"]))])

    res = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vec,
        query_filter=filt,
        limit=1
    )
    if res:
        e_id = res[0].id
        client.delete(collection_name=COLLECTION_NAME, points_selector=[e_id])
        logger.info(f"Removed false positive: {feats['subject']} (ID={e_id})")
        return {"message": f"Removed false positive email: {feats['subject']}"}
    else:
        logger.warning("Email not found.")
        raise HTTPException(status_code=404, detail="Email not found in DB.")

@app.post("/parse_eml")
async def parse_eml(file: UploadFile = File(...)):
    try:
        eml_bytes = await file.read()
        msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)

        subject = msg["subject"] or "No Subject"
        sender = msg["from"] or "Unknown Sender"
        body = extract_eml_body(msg)

        parsed_email = {
            "subject": subject,
            "body": base64.b64encode(body.encode("utf-8")).decode("utf-8"),
            "sender": sender
        }
        return {"message": "Parsed EML", "email": parsed_email}
    except Exception as e:
        logger.error(f"Failed to parse EML: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to parse EML: {e}")


##
# uvicorn app:app --host 0.0.0.0 --port 5000 --reload
##