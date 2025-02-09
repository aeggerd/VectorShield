from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from qdrant_client import QdrantClient
from qdrant_client.http.models import PointStruct, PointsSelector, Filter
from qdrant_client.http.models import FieldCondition, Match, FilterSelector
from qdrant_client.http.exceptions import UnexpectedResponse
from sentence_transformers import SentenceTransformer
from bs4 import BeautifulSoup
import asyncio
from collections import deque
from functools import lru_cache
import hashlib
import uuid
import re
import base64

import numpy as np

# -------------------------------
# 🚀 Initialize Components
# -------------------------------
app = FastAPI(title="Phishing Detection API", version="1.0.0")

# Connect to local Qdrant instance
client = QdrantClient("http://michael-XPS-13-9360:6333")
COLLECTION_NAME = "emails"
# -------------------------------
# 📌 Asynchronous Batch Upsert
# -------------------------------
batch_queue = deque()
BATCH_SIZE = 10  # Adjust for performance vs. memory tradeoff

# Load Embedding Model
model = SentenceTransformer("all-MiniLM-L6-v2")

try:
    client.get_collection(collection_name=COLLECTION_NAME)
    print(f"Collection '{COLLECTION_NAME}' already exists. Skipping creation.")
except UnexpectedResponse as e:
    if "Collection" in str(e) and "doesn" in str(e):
        print(f"Collection '{COLLECTION_NAME}' does not exist. Creating it now...")
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=384, distance=Distance.COSINE)
        )
    else:
        raise  # Re-raise the exception if it's something unexpected


# -------------------------------
# 📌 Request Models (Pydantic)
# -------------------------------
class EmailRequest(BaseModel):
    subject: str
    body: str
    sender: str
    reply_to: Optional[str] = None
    attachments: Optional[List[str]] = []
    type: Optional[str] = None


class AnalyzeResponse(BaseModel):
    phishing_score: int
    confidence_level: str
    closest_match: Optional[str]
    reasons: List[str]

# -------------------------------
# 🔍 Utility Functions
# -------------------------------
def extract_urls(text: str) -> List[str]:
    url_regex = r"https?://[^\s\"<>]+"
    return re.findall(url_regex, text)

def extract_email_features(email: EmailRequest):
    subject = email.subject
    
    body_text = str(base64.b64decode(email.body))[:200]  # First 200 characters
    sender = email.sender
    reply_to = email.reply_to or sender
    attachments = email.attachments or []

    sender_domain = sender.split("@")[-1] if "@" in sender else "unknown"
    reply_to_domain = reply_to.split("@")[-1] if "@" in reply_to else "unknown"

    # Extract links
    soup = BeautifulSoup(str(base64.b64decode(email.body)), "html.parser")
    html_links = [a['href'] for a in soup.find_all('a', href=True)] or []
    text_links = extract_urls(str(base64.b64decode(email.body))) or []

    merged_links = list(set(html_links + text_links))

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
    }

# -------------------------------
# 📌 Caching for Embeddings
# -------------------------------
@lru_cache(maxsize=1000)
def get_cached_embedding(vector_text: str):
    """Returns cached embedding or calculates it if not in cache."""
    return model.encode([vector_text], convert_to_numpy=True).tolist()[0]

async def batch_upsert():
    """Performs batch upsert to Qdrant when the queue reaches BATCH_SIZE."""
    while True:
        if len(batch_queue) >= BATCH_SIZE:
            points = [batch_queue.popleft() for _ in range(BATCH_SIZE)]
            client.upsert(COLLECTION_NAME, points)
            print(f"✅ Upserted {len(points)} points to Qdrant.")
        await asyncio.sleep(1)  # Avoid busy waiting

# Start the batch processing in the background
asyncio.create_task(batch_upsert())

def store_email(email: EmailRequest, label: str) -> str:
    """Prepares and queues an email for batch insertion into Qdrant."""
    email_features = extract_email_features(email)
    email_features["label"] = label

    email_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, email_features["email_hash"]))
    vector_text = f"{email_features['subject']} {email_features['body_preview']} {' '.join(email_features['links'])}"
    
    # Use cached embedding for performance
    vector_embedding = get_cached_embedding(vector_text)

    point = PointStruct(
        id=email_id,
        vector=vector_embedding,
        payload=email_features
    )

    # Queue the point for batch upsert
    batch_queue.append(point)
    return f"✅ Queued {label} email: {email_features['subject']}"

def check_email_similarity(email_features):
    vector_text = f"{email_features['subject']} {email_features['body_preview']} {' '.join(email_features['links'])}"
    vector_embedding = model.encode([vector_text], convert_to_numpy=True).tolist()[0]

    search_result = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vector_embedding,
        limit=5
    )

    phishing_score = 0
    phishing_matches = []
    legitimate_matches = []
    max_similarity = 0
    closest_label = None

    for result in search_result:
        similarity = result.score
        label = result.payload.get("label", "unknown")

        if similarity > max_similarity:
            max_similarity = similarity
            closest_label = label  # Track the label with the highest similarity

        if similarity > 0.8:
            if label == "phishing":
                phishing_score += 50
                phishing_matches.append(result.payload.get("subject", "Unknown"))
            elif label == "legitimate":
                phishing_score -= 20
                legitimate_matches.append(result.payload.get("subject", "Unknown"))

    phishing_score = max(0, min(phishing_score, 100))  # Clamp score between 0 and 100

    reasons = phishing_matches if phishing_matches else ["No strong phishing indicators found."]
    return phishing_score, reasons, closest_label


# -------------------------------
# 📌 API Endpoints
# -------------------------------

@app.post("/insert", summary="Insert Email", description="Inserts an email into Qdrant with its classification (phishing or legitimate).")
def insert_email(email: EmailRequest):
    email_type = email.type.lower() if email.type else ""
    if email_type not in ["phishing", "legitimate"]:
        raise HTTPException(status_code=400, detail="Invalid email type. Must be 'phishing' or 'legitimate'.")

    message = store_email(email, email_type)
    return {"message": message}

@app.post("/analyze", response_model=AnalyzeResponse, summary="Analyze Email", description="Analyzes an email and returns a phishing probability percentage.")
def analyze_email(email: EmailRequest):
    email_features = extract_email_features(email)
    phishing_score, reasons, closest_label = check_email_similarity(email_features)

    confidence_level = "Low"
    if phishing_score >= 70:
        confidence_level = "High"
    elif phishing_score >= 40:
        confidence_level = "Medium"

    return AnalyzeResponse(
        phishing_score=phishing_score,
        confidence_level=confidence_level,
        closest_match=closest_label,
        reasons=reasons if reasons else ["No strong phishing indicators found."]
    )

@app.post("/report_false_positive", summary="Report False Positive", description="Removes a falsely flagged email from Qdrant.")
def report_false_positive(email: EmailRequest):
    email_features = extract_email_features(email)
    
    # Create a vector embedding using the same criteria as in `analyze_email`
    vector_text = f"{email_features['subject']} {email_features['body_preview']} {' '.join(email_features['links'])}"
    vector_embedding = model.encode([vector_text], convert_to_numpy=True).tolist()[0]

    # Search for the closest matching email using the full embedding
    search_result = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vector_embedding,
        limit=1
    )

    if search_result:
        email_id = search_result[0].id

        # Delete the point by its ID using the latest working delete method
        client.delete(
            collection_name=COLLECTION_NAME,
            points_selector={"points": [email_id]}  # Use 'points' key to specify the point IDs
        )
        
        return {"message": f"✅ Removed false positive email: {email_features['subject']}"}

    raise HTTPException(status_code=404, detail="Email not found in the database.")



# -------------------------------
# 🚀 Run FastAPI with Uvicorn
# -------------------------------
# Use the command: uvicorn app:app --host 0.0.0.0 --port 5000 --reload
