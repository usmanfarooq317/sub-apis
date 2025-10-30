# Use Python 3.10 as base image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy dependencies file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy rest of the code
COPY . .

# Expose port used by the app inside container
EXPOSE 5040

# Default command
CMD ["python", "app.py"]
