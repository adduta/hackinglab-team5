FROM python:3.13-bookworm
RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    openssh-client \
    libpcap-dev \
    netcat-traditional \
    iputils-ping \
    net-tools \
    iproute2 \
    nmap \
 && pip install paramiko pyshark