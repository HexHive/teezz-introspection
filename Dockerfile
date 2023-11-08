# syntax=docker/dockerfile:latest
ARG VERSION=focal
ARG CMDLINE_TOOLS_URL=https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip

FROM ubuntu:$VERSION as recorder
ARG CMDLINE_TOOLS_URL

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
        unzip \
        zip \
        git \
        python3-minimal \
        python3-pip \
        python3-venv \
        python3-dev \
        python3-setuptools \
        python3-clang-10 \
        android-tools-adb \
        android-tools-fastboot \
        curl \
        protobuf-compiler \
        openjdk-11-jdk-headless \
        graphviz \
        wget

WORKDIR /root
RUN curl -sL https://deb.nodesource.com/setup_14.x | bash - && \
    apt-get install -y nodejs && \
    npm install frida-compile@10.2.5

WORKDIR /src
RUN --mount=type=bind,source=src,target=/src \
    --mount=type=cache,target=/root/.cache/pip,sharing=locked \
        pip3 install -r requirements.txt

COPY docker/frida-server-14.2.7-android-arm64 /root/frida-server

WORKDIR /root/sdk
ADD --link $CMDLINE_TOOLS_URL /root/sdk/commandlinetools.zip
RUN unzip commandlinetools.zip

ENV PATH="$PATH:/root/sdk/cmdline-tools/bin"

RUN yes | sdkmanager --sdk_root=/root/sdk --install "build-tools;30.0.3"

ENV PATH="$PATH:/root/sdk/build-tools/30.0.3"

