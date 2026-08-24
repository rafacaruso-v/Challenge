FROM ghcr.io/gitleaks/gitleaks:v8.30.1 AS gitleaks
FROM aquasec/trivy:latest AS trivy

FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    apt-transport-https \
    gnupg \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=America/Sao_Paulo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
RUN chmod +x /usr/local/bin/gitleaks

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
RUN chmod +x /usr/local/bin/trivy

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]