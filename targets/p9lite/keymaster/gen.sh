#!/usr/bin/env bash

TARGET_DIR=/root/workdir/aosp

set -ue

PYTHONPATH=/src python3 -m generator \
    "keymaster1_device" \
    $TARGET_DIR/hardware/libhardware/include/hardware/keymaster1.h \
    -I$TARGET_DIR/hardware/libhardware/include/ \
    -I$TARGET_DIR/system/core/include/ \
    -Wall -x c -std=gnu11 -Dbool=_Bool -Dtrue=1 -Dfalse=0 > dump.js


PYTHONPATH=/src python3 -m generator.geninterceptor \
    /interceptor_configs/keystore.hi6250.304f85a1316b7920544162a56f076837.json \
    > interceptor.js

cat interceptor.js dump.js > recorder.js
