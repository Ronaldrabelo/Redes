FROM ubuntu:latest

LABEL maintainer="ronald.rabelo1@gmail.com"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    vim \
    gcc \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

# Compila automaticamente o código ao construir
RUN gcc -o token_request main.c

# Comando padrão
CMD ["./token_request"]
