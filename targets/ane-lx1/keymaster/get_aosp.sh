#!/usr/bin/env bash

# getprop ro.bootimage.build.fingerprint
# Huawei/generic_a15/generic_a15:8.0.0/OPR6.170623.010/jenkin06161628:user/test-keys
# OPR6.170623.010 -> android-8.0.0_r1
TAG="android-8.0.0_r1"
GIT_CMD="git clone --depth 1 --branch $TAG"

if [[ ! -d ./system ]]; then
  mkdir -p system && cd system
  $GIT_CMD https://android.googlesource.com/platform/system/core
  $GIT_CMD https://android.googlesource.com/platform/system/libhidl
  $GIT_CMD https://android.googlesource.com/platform/system/libfmq
  cd -
fi

if [[ ! -d ./hardware ]]; then
  mkdir -p hardware && cd hardware
  $GIT_CMD https://android.googlesource.com/platform/hardware/libhardware
  $GIT_CMD https://android.googlesource.com/platform/hardware/interfaces
  cd -
fi

# copy pre-generated hidl-gen header files to target directories
cp -r /target/aosp_gen/android.hardware.keymaster@3.0_genc++_headers ./hardware/interfaces/keymaster/3.0/
cp -r /target/aosp_gen/android.hidl.base\@1.0_genc++_headers ./system/libhidl/transport/base/1.0/
cp -r /target/aosp_gen/android.hidl.manager@1.0_genc++_headers ./system/libhidl/transport/manager/1.0/