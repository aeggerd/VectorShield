# Use lightweight Python image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

COPY requirements.txt .

# Install dependencies
#RUN pip install --no-cache-dir flask flask-cors qdrant-client sentence-transformers beautifulsoup4
RUN pip install -r requirements.txt


# Copy files
COPY . .

# Expose port for API
EXPOSE 5000

# Run Flask app
CMD ["python", "app.py"]

