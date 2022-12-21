#!/usr/bin/env bash

TARGET_DIR=/in/targets/bullhead/aosp

set -ue

PYTHONPATH=/src python3 -m generator.gendumper \
    "gatekeeper_device" \
    $TARGET_DIR/hardware/libhardware/include/hardware/gatekeeper.h \
    -Wall -x c -std=gnu11 -Dbool=_Bool \
    -I$TARGET_DIR/hardware/libhardware/include/ \
    -I$TARGET_DIR/system/core/include/ \
    > /out/dump.js


# PYTHONPATH=/src python3 -m generator.geninterceptor \
#     /in/generator_data/interceptor_data/gatekeeper.hi6250.c78bffe0c3dec2aa0f9a388c37a753b4.json \
#     > /out/interceptor.js

PYTHONPATH=/src python3 -m generator.geninterceptor \
    /in/generator_data/interceptor_data/gatekeeper.msm8992.b12bc213d19fd23956aaa66277fde2d9.json \
    > /out/interceptor.js

cat /out/interceptor.js /out/dump.js > /out/gk_recorder.js
