FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir paramiko

COPY honeypot.py logger.py ./

# Create logs directory
RUN mkdir -p /app/logs

EXPOSE 22

CMD ["python", "-u", "honeypot.py"]
