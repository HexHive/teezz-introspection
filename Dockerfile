# syntax=docker/dockerfile:latest
ARG VERSION=jammy

FROM ubuntu:$VERSION as recorder

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

ENV TZ=Europe/Zurich
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
        python3-ipdb \
        python3-ipython \
        python3-venv \
        python3.10-dev \
        python3-clang-14 \
        android-tools-adb \
        android-tools-fastboot \
        wget


WORKDIR /src
RUN --mount=type=bind,source=src,target=/src \
    --mount=type=cache,target=/root/.cache/pip,sharing=locked \
        pip install -r requirements.txt
