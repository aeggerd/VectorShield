import asyncio
import base64
import hashlib
import logging
import re
import time
from collections import deque
from functools import lru_cache
from typing import List, Optional

import requests
from email import policy
from email.parser import BytesParser
from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST, start_http_server

# Initialize FastAPI and Jinja2 templates
app = FastAPI(title="VectorShield Web UI", version="1.0.0")
templates = Jinja2Templates(directory="templates")

# Prometheus Metrics
ANALYZE_REQUESTS = Counter("analyze_requests_total", "Total number of analyze requests")
INSERT_REQUESTS = Counter("insert_requests_total", "Total number of insert requests")
FALSE_POSITIVE_REQUESTS = Counter("false_positive_requests_total", "Total number of false positive requests")

# Start Prometheus metrics server on port 8001
start_http_server(8001)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vector-shield-webui")

# API Base URL
API_BASE_URL = "http://localhost:5000"

# -------------------------------
# 🚀 Health and Readiness Checks
# -------------------------------

@app.get("/health", summary="Health Check")
def health_check():
    """Health check to verify the service is running."""
    return JSONResponse(content={"status": "healthy"}, status_code=200)

@app.get("/readiness", summary="Readiness Check")
def readiness_check():
    """Readiness check to ensure dependencies are available (e.g., API connectivity)."""
    try:
        response = requests.get(f"{API_BASE_URL}/metrics")
        if response.status_code == 200:
            return JSONResponse(content={"status": "ready"}, status_code=200)
    except requests.RequestException:
        pass
    return JSONResponse(content={"status": "not ready"}, status_code=503)

# -------------------------------
# 🚀 Web UI Routes
# -------------------------------

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Render the main web interface."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze")
async def analyze_email(subject: str = Form(...), body: str = Form(...), sender: str = Form(...)):
    """Send the email to the /analyze API and display the results."""
    ANALYZE_REQUESTS.inc()
    try:
        response = requests.post(
            f"{API_BASE_URL}/analyze",
            json={
                "subject": subject,
                "body": base64.b64encode(body.encode()).decode(),
                "sender": sender
            }
        )
        response.raise_for_status()
        result = response.json()
        logger.info(f"Analyzed email: {subject} - Result: {result}")
        return {"status": "success", "result": result}
    except requests.RequestException as e:
        logger.error(f"Failed to analyze email: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze email.")

@app.post("/insert")
async def insert_email(subject: str = Form(...), body: str = Form(...), sender: str = Form(...), email_type: str = Form(...)):
    """Insert the email into the vector database."""
    INSERT_REQUESTS.inc()
    try:
        response = requests.post(
            f"{API_BASE_URL}/insert",
            json={
                "subject": subject,
                "body": base64.b64encode(body.encode()).decode(),
                "sender": sender,
                "type": email_type
            }
        )
        response.raise_for_status()
        logger.info(f"Inserted email: {subject}")
        return {"status": "success", "message": response.json()["message"]}
    except requests.RequestException as e:
        logger.error(f"Failed to insert email: {e}")
        raise HTTPException(status_code=500, detail="Failed to insert email.")

@app.post("/report_false_positive")
async def report_false_positive(subject: str = Form(...), body: str = Form(...), sender: str = Form(...)):
    """Report an email as a false positive to remove it from the vector database."""
    FALSE_POSITIVE_REQUESTS.inc()
    try:
        response = requests.post(
            f"{API_BASE_URL}/report_false_positive",
            json={
                "subject": subject,
                "body": base64.b64encode(body.encode()).decode(),
                "sender": sender
            }
        )
        response.raise_for_status()
        logger.info(f"Reported false positive: {subject}")
        return {"status": "success", "message": response.json()["message"]}
    except requests.RequestException as e:
        logger.error(f"Failed to report false positive: {e}")
        raise HTTPException(status_code=500, detail="Failed to report false positive.")

@app.post("/upload_eml")
async def upload_eml(file: UploadFile = File(...)):
    """Parse an uploaded EML file and display the extracted content."""
    try:
        # Parse the EML file
        raw_email = await file.read()
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)

        subject = msg["subject"] or "No Subject"
        sender = msg["from"] or "unknown@unknown.com"
        body = msg.get_body(preferencelist=("plain", "html")).get_content() if msg.get_body() else "No Body"

        logger.info(f"Parsed EML file: {subject} from {sender}")

        # Return the parsed content to the web UI for confirmation and further actions
        return {
            "subject": subject,
            "body": body,
            "sender": sender
        }
    except Exception as e:
        logger.error(f"Failed to parse EML file: {e}")
        raise HTTPException(status_code=500, detail="Failed to parse EML file.")

@app.get("/metrics", response_class=HTMLResponse)
async def metrics():
    """Expose Prometheus metrics at /metrics."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
