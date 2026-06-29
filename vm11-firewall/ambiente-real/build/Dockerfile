# firewall/Dockerfile
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nftables \
    iproute2 \
    iputils-ping \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install flask --break-system-packages 2>/dev/null || pip3 install flask ldap3

COPY app.py /app/app.py
COPY templates/ /app/templates/

WORKDIR /app
EXPOSE 5000

CMD ["python3", "app.py"]
