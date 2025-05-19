FROM python:3-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache build-base

# Copy requirements if you have one, else install directly
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code
COPY . .

# Expose the port FastAPI will run on
EXPOSE 8000

# Run the app with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
