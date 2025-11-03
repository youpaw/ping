FROM debian:bookworm

RUN apt update && apt install -y \
    build-essential \
    gdb \
    gdbserver \
    inetutils-ping \
    python3 \
    && apt clean

RUN echo "deb http://deb.debian.org/debian testing main" >> /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y -t testing gcc-14 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100

WORKDIR /app
USER root

