# Use official slim Python 3.11 image for smaller size and security
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy only requirements to leverage Docker cache
COPY requirements.txt .

# Upgrade pip and install dependencies without cache to keep image small
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Create directory for ChromaDB persistent data
RUN mkdir -p ./chroma_db

# Expose port if your app serves an API (optional)
# EXPOSE 8000

# Default command to run your enricher service
CMD ["python", "main.py"]