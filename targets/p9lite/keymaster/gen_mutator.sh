#!/usr/bin/env bash

TARGET_DIR=/root/workdir/aosp

set -ue

mkdir -p $TARGET_DIR

PYTHONPATH=/src python3 -m protofy \
    "keymaster1_device" \
    $TARGET_DIR/hardware/libhardware/include/hardware/keymaster1.h \
    -I$TARGET_DIR/hardware/libhardware/include/ \
    -I$TARGET_DIR/system/core/include/ \
    -Wall -x c -std=gnu11 -Dbool=_Bool -Dtrue=1 -Dfalse=0
