FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY init_db.py .
COPY app.py .
# Inicia la DB al construir la imagen
RUN python init_db.py

EXPOSE 5000
CMD ["python", "app.py"]
