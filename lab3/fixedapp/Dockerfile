FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY init_db.py .
COPY app.py .
RUN python init_db.py

EXPOSE 5001
CMD ["python", "app.py"]
