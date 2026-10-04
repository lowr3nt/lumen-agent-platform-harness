# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Minimal runtime image
FROM python:3.12-slim AS runner

WORKDIR /app

# Create unprivileged system user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Copy installed dependencies to standard system site-packages
COPY --from=builder /install /usr/local

# Copy application source code
COPY gateway/ ./gateway/

# Set Python environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Set user permissions
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 8080

CMD ["sh", "-c", "exec uvicorn gateway.server:app --host 0.0.0.0 --port ${PORT}"]