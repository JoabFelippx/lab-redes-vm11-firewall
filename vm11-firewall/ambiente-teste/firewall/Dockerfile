# firewall/Dockerfile
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nftables \
    iproute2 \
    tcpdump \
    curl \
    iputils-ping \
    netcat \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install flask --break-system-packages 2>/dev/null || pip3 install flask ldap3

COPY nftables.conf /etc/nftables.conf
COPY app.py /app/app.py
COPY templates/ /app/templates/

WORKDIR /app
EXPOSE 5000

CMD sysctl -w net.ipv4.ip_forward=1 && \
    nft -f /etc/nftables.conf && \
    python3 app.py
