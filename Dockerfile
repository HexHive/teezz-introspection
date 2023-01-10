# syntax=docker/dockerfile:latest
ARG VERSION=bionic

FROM ubuntu:$VERSION as recorder

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

ENV TZ=Europe/Zurich
ENV PYTHONPATH=$PYTHONPATH:/src/
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install base packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        make \
        git \
        python3-minimal \
        python3-pip \
        python3-venv \
        python3-dev \
        python3-setuptools \
        python3-clang-10 \
        android-tools-adb \
        android-tools-fastboot \
        wget \
        npm

WORKDIR /src
RUN --mount=type=bind,source=src,target=/src \
    --mount=type=cache,target=/root/.cache/pip,sharing=locked \
        pip3 install -r requirements.txt

COPY docker/frida-server-14.2.7-android-arm64 /root/frida-server
