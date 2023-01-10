#!/usr/bin/env bash

TAG="android-9.0.0_r34"
GIT_CMD="git clone --depth 1 --branch $TAG"
mkdir -p aosp && cd aosp

mkdir -p system && cd system
$GIT_CMD https://android.googlesource.com/platform/system/core
$GIT_CMD https://android.googlesource.com/platform/system/libhidl
$GIT_CMD https://android.googlesource.com/platform/system/libfmq
$GIT_CMD https://android.googlesource.com/platform/system/keymaster
cd -

mkdir -p hardware && cd hardware
$GIT_CMD https://android.googlesource.com/platform/hardware/libhardware
$GIT_CMD https://android.googlesource.com/platform/hardware/interfaces
cd -

mkdir -p external && cd external
$GIT_CMD https://android.googlesource.com/platform/external/clang
mkdir optee && cd optee
git clone https://android.googlesource.com/platform/external/optee/apps -b "upstream-master"
cd ../../

$GIT_CMD https://android.googlesource.com/platform/bionic

mkdir prebuilts && cd prebuilts
mkdir -p gcc/linux-x86/aarch64/aarch64-linux-android-4.9 && cd gcc/linux-x86/aarch64/aarch64-linux-android-4.9
$GIT_CMD https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9
cd -
mkdir -p clang/host/linux-x86/ && cd clang/host/linux-x86
$GIT_CMD https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86
cd -
mkdir -p build-tools
git clone https://android.googlesource.com/platform/prebuilts/build-tools #We need master branch for hidl-gen
cd -
cd -
