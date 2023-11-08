#!/usr/bin/env bash

TAG=android-7.1.2_r39
GIT_CMD="git clone --depth 1 --branch $TAG"


if [[ ! -d ./system ]]; then
    mkdir -p system && cd system
    $GIT_CMD https://android.googlesource.com/platform/system/core
    cd -
fi

if [[ ! -d ./hardware ]]; then
    mkdir -p hardware && cd hardware
    $GIT_CMD https://android.googlesource.com/platform/hardware/libhardware
    cd -
fi

if [[ ! -d ./external ]]; then
    mkdir -p external && cd external
    $GIT_CMD https://android.googlesource.com/platform/external/clang
    $GIT_CMD https://android.googlesource.com/platform/external/bison
    cd -
fi

if [[ ! -d ./bionic ]]; then
    $GIT_CMD https://android.googlesource.com/platform/bionic
fi
