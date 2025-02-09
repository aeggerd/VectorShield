import os
import pandas as pd
import requests
import base64
import random

# -------------------------------
# 📁 Setup File Paths
# -------------------------------
current_dir = os.path.dirname(os.path.abspath("__file__"))
csv_file_path = os.path.join(current_dir, "enron_data_fraud_labeled.csv")

# -------------------------------
# 📦 Load Dataset
# -------------------------------
data = pd.read_csv(csv_file_path)
print("Dataset loaded successfully!")

# -------------------------------
# 📌 Helper Functions
# -------------------------------
def get_email_type(label):
    """Determines email type based on the 'Label' field."""
    return "phishing" if label == 1 else "legitimate"

# -------------------------------
# 🚀 Test Script Configuration
# -------------------------------
analyze_api_url = "http://localhost:5000/analyze"
sample_size = 1000  # Number of random entries to test

# Select 1000 random rows from the dataset
sample_data = data.sample(n=sample_size, random_state=42)
total_tested = 0
correct_classifications = 0
false_positives = 0
false_negatives = 0

# -------------------------------
# 🔍 Validate Each Email
# -------------------------------
for index, row in sample_data.iterrows():
    try:
        email_body = row["Body"]
        email_subject = row["Subject"] if pd.notna(row["Subject"]) else "No Subject"
        email_sender = row["From"] if pd.notna(row["From"]) else "unknown@enron.com"
        expected_type = get_email_type(row["Label"])

        # Prepare the request payload
        payload = {
            "subject": email_subject,
            "body": base64.b64encode(email_body.encode("utf-8")).decode("utf-8"),
            "sender": email_sender
        }

        # Send the POST request to the analyze endpoint
        response = requests.post(analyze_api_url, json=payload)
        response_data = response.json()

        if response.status_code == 200:
            total_tested += 1
            predicted_type = "phishing" if response_data["phishing_score"] >= 70 else "legitimate"

            if predicted_type == expected_type:
                correct_classifications += 1
            elif predicted_type == "phishing" and expected_type == "legitimate":
                false_positives += 1
            elif predicted_type == "legitimate" and expected_type == "phishing":
                false_negatives += 1

        else:
            print(f"Error analyzing row {index}: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"An error occurred at row {index}: {e}")

# -------------------------------
# 📊 Generate Final Report
# -------------------------------
accuracy = (correct_classifications / total_tested) * 100 if total_tested > 0 else 0
false_positive_rate = (false_positives / total_tested) * 100 if total_tested > 0 else 0
false_negative_rate = (false_negatives / total_tested) * 100 if total_tested > 0 else 0

print("\n📊 Test Summary:")
print(f"Total Emails Tested: {total_tested}")
print(f"Correct Classifications: {correct_classifications}")
print(f"False Positives: {false_positives} ({false_positive_rate:.2f}%)")
print(f"False Negatives: {false_negatives} ({false_negative_rate:.2f}%)")
print(f"Overall Accuracy: {accuracy:.2f}%")
