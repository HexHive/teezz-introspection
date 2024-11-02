#!/usr/bin/env bash

TARGET_DIR=/root/workdir/aosp

set -ue

mkdir -p $TARGET_DIR

PYTHONPATH=/src python3 -m generator \
    "IGatekeeper" \
    $TARGET_DIR/hardware/interfaces/gatekeeper/1.0/android.hardware.gatekeeper@1.0_genc++_headers/gen/android/hardware/gatekeeper/1.0/IGatekeeper.h \
    -I$TARGET_DIR/hardware/interfaces/gatekeeper/1.0/android.hardware.gatekeeper@1.0_genc++_headers/gen \
    -I$TARGET_DIR/system/libhidl/transport/base/1.0/android.hidl.base@1.0_genc++_headers/gen \
    -I$TARGET_DIR/system/libhidl/transport/manager/1.0/android.hidl.manager@1.0_genc++_headers/gen \
    -I$TARGET_DIR/system/libhidl/base/include/ \
    -I$TARGET_DIR/system/core/libcutils/include/ \
    -I$TARGET_DIR/system/core/libutils/include/ \
    -I$TARGET_DIR/system/core/libsystem/include/ \
    -I$TARGET_DIR/hardware/libhardware/include/ \
    -x c++ -std=c++17 -Wall \
    > dump.js

PYTHONPATH=/src python3 -m generator.geninterceptor \
    /interceptor_configs/gatekeeper.hikey.json \
    > interceptor.js

cat interceptor.js dump.js > recorder.js
