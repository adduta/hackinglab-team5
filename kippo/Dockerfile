FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/home/kippo/.local/bin:$PATH"

# Install dependencies
RUN apt-get update && apt-get install -y \
    git python python-dev python-pip libssl-dev libffi-dev openssl && \
    useradd -m kippo

USER kippo
WORKDIR /home/kippo

# Clone Kippo
RUN git clone https://github.com/desaster/kippo.git

# Install known-compatible packages
RUN pip install --user --index-url https://pypi.python.org/simple \
    twisted==15.1.0 pycrypto==2.6.1 pyasn1==0.4.8 zope.interface==4.0.5

ENV PATH="/home/kippo/.local/bin:$PATH"


# Copy example config
RUN cp kippo/kippo.cfg.dist kippo/kippo.cfg

WORKDIR /home/kippo/kippo
CMD ["bash", "-c", "~/.local/bin/twistd --nodaemon -y kippo.tac"]

