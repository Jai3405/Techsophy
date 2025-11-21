# Vulnerable Dockerfile for testing
FROM python:latest

# Run as root (security risk)
USER root

# Expose insecure ports
EXPOSE 22
EXPOSE 3389
EXPOSE 3306

# Hardcoded secret in ENV
ENV API_KEY=secret123
ENV DATABASE_PASSWORD=admin_password_123

# Install packages without cleanup
RUN apt-get update && \
    apt-get install -y curl wget vim netcat telnet

# Copy application
COPY . /app
WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# No HEALTHCHECK defined

# No USER directive to switch from root

CMD ["python", "vulnerable_app.py"]
