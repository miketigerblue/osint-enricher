FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# create chroma dir
RUN mkdir -p ./chroma_db


CMD ["python", "main.py"]
