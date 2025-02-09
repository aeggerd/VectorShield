# **VectorShield: Advanced Spam Detection with a Vector Database**

![VectorShield Logo](./logo.png)

VectorShield is an advanced spam detection tool designed to complement existing spam scanners by leveraging vector databases and machine learning to detect **similar patterns in spam emails**. Traditional spam detection engines often miss subtle patterns that are easy for humans to spot, but difficult for rule-based scanners. VectorShield addresses this challenge by analyzing email content and identifying **similar emails** based on vector representations.

This tool is intended to **run in addition to existing spam scanners** and improve spam detection accuracy over time by learning from user feedback on which emails are correctly or incorrectly classified.

---

## **Features**
- **Vector-based Email Analysis**: Uses a vector database to find emails with similar content, detecting spam patterns effectively.  
- **API for Real-Time Integration**: Offers a REST API for inserting, analyzing, and managing emails.  
- **False Positive Handling**: An API endpoint to remove mistakenly classified emails from the phishing database, allowing continuous improvement.  
- **Self-Improving System**: Continuously learns from new emails to enhance its detection accuracy over time.

---

## **API Documentation**

### **1. Insert Email**  
**Endpoint:** `POST /insert`  
Inserts a new email into the vector database with a classification (`phishing` or `legitimate`).

#### **Request Example:**
```json
{
  "subject": "Important Security Update",
  "body": "VGhpcyBpcyBhIHNhbXBsZSBlbWFpbCBib2R5Lg==",
  "sender": "security@example.com",
  "type": "phishing"
}
```

- **`subject`**: Subject of the email.  
- **`body`**: Base64-encoded email body.  
- **`sender`**: Email sender address.  
- **`type`**: Email type (`phishing` or `legitimate`).  

#### **Response Example:**
```json
{
  "message": "✅ Stored phishing email: Important Security Update"
}
```

---

### **2. Analyze Email**  
**Endpoint:** `POST /analyze`  
Analyzes an email and returns a **phishing probability score** with explanations.

#### **Request Example:**
```json
{
  "subject": "Congratulations! You've won a prize!",
  "body": "VGhpcyBpcyBhIGZha2UgZW1haWwgYm9keS4=",
  "sender": "prizes@example.com"
}
```

#### **Response Example:**
```json
{
  "phishing_score": 85,
  "confidence_level": "High",
  "closest_match": "phishing",
  "reasons": [
    "Similar to known phishing email: Prize Notification",
    "Similar to known phishing email: Win a Free Gift!"
  ]
}
```

- **`phishing_score`**: Probability that the email is phishing (0–100%).  
- **`confidence_level`**: Low, Medium, or High.  
- **`closest_match`**: Label of the closest matching email.  
- **`reasons`**: List of similar emails and reasons for the classification.

---

### **3. Remove False Positives**  
**Endpoint:** `POST /report_false_positive`  
Removes an incorrectly flagged email from the phishing database.

#### **Request Example:**
```json
{
  "subject": "Meeting Reminder",
  "body": "VGhpcyBpcyBhIG1lZXRpbmcgcmVtaW5kZXIu",
  "sender": "noreply@example.com"
}
```

#### **Response Example:**
```json
{
  "message": "✅ Removed false positive email: Meeting Reminder"
}
```

---

## **How It Works**
1. **Email Insertion**: Every email is vectorized using a sentence-transformer model and stored in a **Qdrant vector database**.
2. **Similarity Search**: When an email is analyzed, the system searches for similar emails in the vector database and calculates a phishing probability based on known classifications.
3. **Continuous Learning**: The system improves its accuracy over time by integrating feedback on false positives and legitimate emails.

---

## **Getting Started**

### **Prerequisites**
- **Python 3.9+**  
- **Qdrant Vector Database**  
- **FastAPI**  
- **Sentence-Transformers**

### **Run the Project**
1. Clone the repository:
   ```bash
   git clone https://github.com/aeggerd/VectorShield.git
   cd VectorShield
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start Qdrant (Docker Compose):
   ```bash
   docker-compose up -d
   ```

4. Run the FastAPI server:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 5000 --reload
   ```

5. Open the API docs at [http://localhost:5000/docs](http://localhost:5000/docs).

---

## **License**
This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

---

## **Future Plans**
- Add support for multiple vector databases (e.g., Pinecone, Milvus).  
- Introduce active learning for automatic reclassification.  
- Improve spam pattern clustering for better visualization.

---

Let me know if you want to adjust the tone (technical vs user-friendly) or expand any section! 😊