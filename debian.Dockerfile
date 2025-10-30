FROM debian:bookworm

RUN apt update && apt install -y \
    build-essential \
    gdb \
    gdbserver \
    inetutils-ping \
    && apt clean

WORKDIR /app
USER root

