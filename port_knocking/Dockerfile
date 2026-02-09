FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

COPY knock_server.py knock_client.py ./

CMD ["python3", "knock_server.py"]