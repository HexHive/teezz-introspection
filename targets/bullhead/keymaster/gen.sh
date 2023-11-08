#!/usr/bin/env bash

TARGET_DIR=/root/workdir/aosp

set -ue

PYTHONPATH=/src python3 -m generator.gendumper \
    "keymaster1_device" \
    $TARGET_DIR/hardware/libhardware/include/hardware/keymaster1.h \
    -I$TARGET_DIR/hardware/libhardware/include/ \
    -I$TARGET_DIR/system/core/include/ \
    -Wall -x c -std=gnu11 -Dbool=_Bool \
    > dump.js


PYTHONPATH=/src python3 -m generator.geninterceptor \
    /interceptor_configs/keystore.msm8992.023b83490da540a3fe637be86d62fb95.json \
    > interceptor.js

cat interceptor.js dump.js > recorder.js
