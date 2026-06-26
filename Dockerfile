# Dockerfile
FROM python:3.10-slim

# Optional: avoid tz prompts in some bases
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default: interactive shell (compose can override)
CMD ["/bin/bash"]
