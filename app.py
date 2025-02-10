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

import numpy as np
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
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
# 1) Logging Setup (Unified for Uvicorn + App)
# -------------------------------------------------------

LOG_LEVEL = "INFO"
LOG_FORMAT = "[%(asctime)s] %(levelname)s %(name)s - %(message)s"

# Set up a root logger
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
logger = logging.getLogger("phishing_api")
logger.setLevel(logging.INFO)

# Force Uvicorn loggers to use the same handlers/format:
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
# 2) Prometheus Metrics & Middleware
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
    """
    Middleware to record request duration and status codes for Prometheus.
    """
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        request_duration = time.time() - start_time

        method = request.method
        path = request.url.path
        status_code = response.status_code

        # Record metrics
        REQUEST_LATENCY.labels(method=method, path=path).observe(request_duration)
        REQUEST_COUNT.labels(method=method, path=path, status_code=status_code).inc()

        return response

# -------------------------------------------------------
# 3) FastAPI Initialization
# -------------------------------------------------------
app = FastAPI(title="Phishing Detection API", version="1.0.0")
app.add_middleware(PrometheusMiddleware)

# -------------------------------------------------------
# 4) Qdrant Setup
# -------------------------------------------------------
client = QdrantClient("http://michael-XPS-13-9360:6333")
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
# 5) Prepare background batch upsert
# -------------------------------------------------------
batch_queue = deque()
BATCH_SIZE = 10  # Flush after 10 inserts
FLUSH_INTERVAL = 5  # ...or after 5 seconds if not reached 10 inserts

# Load embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")

@lru_cache(maxsize=1000)
def get_cached_embedding(vector_text: str):
    """Returns a cached embedding or computes it if not in cache."""
    return model.encode([vector_text], convert_to_numpy=True).tolist()[0]

async def batch_upsert():
    """
    Performs batch upsert to Qdrant when the queue reaches BATCH_SIZE
    or 5 seconds have passed since last flush, whichever comes first.
    """
    last_upsert_time = time.time()

    while True:
        elapsed = time.time() - last_upsert_time
        # If queue is big enough OR enough time has elapsed, flush
        if len(batch_queue) >= BATCH_SIZE or (elapsed >= FLUSH_INTERVAL and len(batch_queue) > 0):
            # Take all points in the queue and upsert them
            points = []
            while batch_queue:
                points.append(batch_queue.popleft())

            client.upsert(COLLECTION_NAME, points)
            logger.info(f"✅ Upserted {len(points)} points to Qdrant.")

            last_upsert_time = time.time()

        await asyncio.sleep(1)

@app.on_event("startup")
async def startup_event():
    """Startup event to initialize background batch processing."""
    asyncio.create_task(batch_upsert())

# -------------------------------------------------------
# 6) Pydantic Models
# -------------------------------------------------------
class EmailRequest(BaseModel):
    subject: str
    body: str
    sender: str
    reply_to: Optional[str] = None
    attachments: Optional[List[str]] = []
    type: Optional[str] = None
    customerId: Optional[str] = None  # to separate emails by customer

class AnalyzeResponse(BaseModel):
    phishing_score: int
    confidence_level: str
    closest_match: Optional[str]
    reasons: List[str]

# -------------------------------------------------------
# 7) Utility Functions
# -------------------------------------------------------
def extract_urls(text: str) -> List[str]:
    """Extract all http/https URLs from text."""
    url_regex = r"https?://[^\s\"<>]+"
    return re.findall(url_regex, text)

def extract_email_features(email: EmailRequest):
    """Extract relevant features (subject, body preview, links, domains, etc.)."""
    decoded_body = base64.b64decode(email.body)
    # Safely decode up to 200 characters to avoid extremely large logs
    body_text = decoded_body[:200].decode(errors="replace")

    subject = email.subject
    sender = email.sender
    reply_to = email.reply_to or sender
    attachments = email.attachments or []
    customer_id = email.customerId  # We'll store it in the payload

    sender_domain = sender.split("@")[-1] if "@" in sender else "unknown"
    reply_to_domain = reply_to.split("@")[-1] if "@" in reply_to else "unknown"

    # Extract links (both HTML-based and text-based)
    soup = BeautifulSoup(decoded_body, "html.parser")
    html_links = [a['href'] for a in soup.find_all('a', href=True)]
    text_links = extract_urls(decoded_body.decode(errors="replace"))

    merged_links = list(set(html_links + text_links))

    # Create a hash that identifies the email content (for stable ID creation)
    email_string = subject + body_text + "".join(merged_links) + sender_domain
    email_hash = hashlib.sha256(email_string.encode()).hexdigest()

    return {
        "subject": subject,
        "body_preview": body_text,
        "links": merged_links,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "attachments": attachments,
        "email_hash": email_hash,
        "customerId": customer_id,
    }

def store_email(email: EmailRequest, label: str) -> str:
    """Prepare and queue an email for batch insertion into Qdrant."""
    email_features = extract_email_features(email)
    email_features["label"] = label

    # Create a stable ID by hashing content + label
    email_id_str = email_features["email_hash"] + label
    email_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, email_id_str))

    # Prepare the text for embedding
    vector_text = f"{email_features['subject']} {email_features['body_preview']} {' '.join(email_features['links'])}"
    vector_embedding = get_cached_embedding(vector_text)

    point = PointStruct(
        id=email_id,
        vector=vector_embedding,
        payload=email_features
    )

    # Queue the point for asynchronous batch upsert
    batch_queue.append(point)
    logger.info(
        f"Queued {label} email: {email_features['subject']} "
        f"(customerId={email_features.get('customerId')}, ID={email_id})"
    )
    return f"✅ Queued {label} email: {email_features['subject']}"

def check_email_similarity(email_features):
    """
    Search for up to 5 similar emails for the same customerId (if provided),
    compute a phishing score, and determine the closest label.
    """
    vector_text = f"{email_features['subject']} {email_features['body_preview']} {' '.join(email_features['links'])}"
    vector_embedding = get_cached_embedding(vector_text)

    # Filter by customerId if provided
    filter_ = None
    if email_features.get("customerId"):
        filter_ = Filter(
            must=[FieldCondition(key="customerId", match=MatchValue(value=email_features["customerId"]))]
        )

    search_result = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vector_embedding,
        query_filter=filter_,
        limit=5
    )

    phishing_score = 0.0
    phishing_matches = []
    legitimate_matches = []
    max_similarity = 0.0
    closest_label = None

    for result in search_result:
        similarity = result.score
        label = result.payload.get("label", "unknown")

        # Track highest similarity
        if similarity > max_similarity:
            max_similarity = similarity
            closest_label = label

        # Weighted scoring by similarity
        if label == "phishing":
            # heavily penalize if we see a close phishing match
            phishing_score += 50 * similarity
            phishing_matches.append(result.payload.get("subject", "Unknown"))
        elif label == "legitimate":
            # reduce penalty if we see a close legitimate match
            phishing_score -= 20 * similarity
            legitimate_matches.append(result.payload.get("subject", "Unknown"))

    # Clamp final phishing_score to [0, 100]
    if phishing_score < 0:
        phishing_score = 0
    elif phishing_score > 100:
        phishing_score = 100

    phishing_score = int(phishing_score)
    reasons = []
    if phishing_matches:
        reasons.append(f"Similar to known phishing emails: {phishing_matches}")
    if not phishing_matches and not legitimate_matches:
        reasons.append("No strong phishing or legitimate indicators found.")

    return phishing_score, reasons, closest_label

# -------------------------------------------------------
# 8) API Endpoints
# -------------------------------------------------------

@app.get("/metrics", summary="Prometheus metrics")
def metrics():
    """
    Expose Prometheus metrics at /metrics
    """
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/insert", summary="Insert Email", description="Inserts an email into Qdrant with classification (phishing or legitimate).")
def insert_email(email: EmailRequest):
    logger.info(f"Received /insert request with subject: {email.subject}")
    email_type = email.type.lower() if email.type else ""
    if email_type not in ["phishing", "legitimate"]:
        logger.error("Invalid email type supplied. Must be 'phishing' or 'legitimate'.")
        raise HTTPException(status_code=400, detail="Invalid email type. Must be 'phishing' or 'legitimate'.")

    message = store_email(email, email_type)
    return {"message": message}

@app.post("/analyze", response_model=AnalyzeResponse, summary="Analyze Email", description="Analyzes an email and returns a phishing probability percentage.")
def analyze_email(email: EmailRequest):
    logger.info(f"Received /analyze request with subject: {email.subject}")
    email_features = extract_email_features(email)
    phishing_score, reasons, closest_label = check_email_similarity(email_features)

    if phishing_score >= 70:
        confidence_level = "High"
    elif phishing_score >= 40:
        confidence_level = "Medium"
    else:
        confidence_level = "Low"

    logger.info(
        f"Analysis result: phishing_score={phishing_score}, "
        f"confidence_level={confidence_level}, closest_match={closest_label}, "
        f"customerId={email_features.get('customerId')}"
    )

    return AnalyzeResponse(
        phishing_score=phishing_score,
        confidence_level=confidence_level,
        closest_match=closest_label,
        reasons=reasons
    )

@app.post("/report_false_positive", summary="Report False Positive", description="Removes a falsely flagged email from Qdrant.")
def report_false_positive(email: EmailRequest):
    logger.info(f"Received /report_false_positive with subject: {email.subject}")
    email_features = extract_email_features(email)

    vector_text = f"{email_features['subject']} {email_features['body_preview']} {' '.join(email_features['links'])}"
    vector_embedding = get_cached_embedding(vector_text)

    # Filter by customerId if provided
    filter_ = None
    if email_features.get("customerId"):
        filter_ = Filter(
            must=[FieldCondition(key="customerId", match=MatchValue(value=email_features["customerId"]))]
        )

    search_result = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vector_embedding,
        query_filter=filter_,
        limit=1
    )

    if search_result:
        email_id = search_result[0].id
        client.delete(
            collection_name=COLLECTION_NAME,
            points_selector=[email_id]  # pass as list of IDs
        )
        logger.info(f"Removed false positive email: {email_features['subject']} (ID={email_id})")
        return {"message": f"✅ Removed false positive email: {email_features['subject']}"}
    else:
        logger.warning(f"Email not found in the database: {email_features['subject']}")
        raise HTTPException(status_code=404, detail="Email not found in the database.")

# -------------------------------------------------------
# 9) Run with Uvicorn:
#    uvicorn app:app --host 0.0.0.0 --port 5000 --reload
# -------------------------------------------------------
