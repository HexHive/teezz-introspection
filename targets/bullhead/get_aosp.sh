#!/usr/bin/env bash

TAG=android-7.1.2_r39
GIT_CMD="git clone --depth 1 --branch $TAG"

mkdir -p system && cd system
$GIT_CMD https://android.googlesource.com/platform/system/core
cd -

mkdir -p hardware && cd hardware
$GIT_CMD https://android.googlesource.com/platform/hardware/libhardware
cd -

mkdir -p external && cd external
$GIT_CMD https://android.googlesource.com/platform/external/clang
$GIT_CMD https://android.googlesource.com/platform/external/bison
cd -

$GIT_CMD https://android.googlesource.com/platform/bionic

mkdir -p prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9 && cd prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9
$GIT_CMD https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9
cd -
