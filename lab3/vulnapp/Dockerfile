FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY init_db.py .
COPY app.py .
COPY log_utils.py .
RUN python init_db.py

EXPOSE 5000
CMD ["python", "app.py"]
