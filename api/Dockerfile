# Use official Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /api

# Copy files
COPY requirements.txt .
COPY app.py .
COPY iot_anomaly_pipeline.pkl .
COPY column_stats.json .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 8000

# Start FastAPI with uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
