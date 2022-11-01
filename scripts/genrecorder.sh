#!/usr/bin/env bash

################################################################################
# cpp keymaster
################################################################################

# LD_LIBRARY_PATH=. python -m generator.gendumper "KeymasterDevice" ./generator_data/aosp/KeymasterDevice.hpp -Wall -I./generator_data/aosp/libhardware/include/ -I./generator_data/aosp/core/libcutils/include/ -I./generator_data/aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ -I./generator_data/aosp/ -I./generator_data/aosp/libhidl/base/include/ -I/usr/include/c++/6/ -I/usr/include/x86_64-linux-gnu/c++/6/ -I./generator_data/aosp/core/libutils/include/ -I./generator_data/aosp/libfmq/base/ > ./tmp/dump.js

# optee
# python -m generator.geninterceptor ./generator_data/interceptor_data/android.hardware.keymaster@3.0-service.optee.json > ./tmp/interceptor.js

# marlin
# python -m generator.geninterceptor ./generator_data/interceptor_data/keystore_3.0_marlin.json > ./tmp/interceptor.js

# rest
# python -m generator.geninterceptor ./generator_data/interceptor_data/keystore_3.0.json > ./tmp/interceptor.js

# cat ./tmp/interceptor.js ./tmp/dump.js > ./tmp/recorder_km3.js


################################################################################
# c keymaster
################################################################################

# LD_LIBRARY_PATH=. python -m generator.gendumper "keymaster1_device" ./generator_data/aosp/libhardware/include/hardware/keymaster1.hpp -Wall -I./generator_data/aosp/libhardware/include/ -I./generator_data/aosp/core/libcutils/include/ -I./generator_data/aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ -I./generator_data/aosp/ -I./generator_data/aosp/libhidl/base/include/ -I/usr/include/c++/6/ -I/usr/include/x86_64-linux-gnu/c++/6/ -I./generator_data/aosp/core/libutils/include/ -I./generator_data/aosp/libfmq/base/ > ./tmp/dump.js

# msm
# python -m generator.geninterceptor ./generator_data/interceptor_data/keystore.msm8992.023b83490da540a3fe637be86d62fb95.json > ./tmp/interceptor.js

# hisi
# python -m generator.geninterceptor ./generator_data/interceptor_data/keystore.hi6250.304f85a1316b7920544162a56f076837.json > ./tmp/interceptor.js

# cat ./tmp/interceptor.js ./tmp/dump.js > ./tmp/recorder_km1.js


################################################################################
# cpp gatekeeper
################################################################################

# LD_LIBRARY_PATH=. python -m generator.gendumper "Gatekeeper" ./generator_data/aosp/Gatekeeper.hpp -Wall -I./generator_data/aosp/libhardware/include/ -I./generator_data/aosp/core/libcutils/include/ -I./generator_data/aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ -I./generator_data/aosp/ -I./generator_data/aosp/libhidl/base/include/ -I/usr/include/c++/6/ -I/usr/include/x86_64-linux-gnu/c++/6/ -I./generator_data/aosp/core/libutils/include/ -I./generator_data/aosp/libfmq/base > ./tmp/dump.js
# 
# python -m generator.geninterceptor ./generator_data/interceptor_data/gatekeeper_1.0.json > ./tmp/interceptor.js
# 
# cat ./tmp/interceptor.js ./tmp/dump.js > ./tmp/recorder_gk1.js

################################################################################
# c gatekeeper
################################################################################

# LD_LIBRARY_PATH=. python -m generator.gendumper "gatekeeper_device" ./generator_data/aosp/libhardware/include/hardware/gatekeeper.h -Wall -I./generator_data/aosp/libhardware/include/ -I/usr/include/x86_64-linux-gnu/ -I./generator_data/aosp/core/libcutils/include/ -I./generator_data/aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ -I./generator_data/aosp/ -I./generator_data/aosp/libhidl/base/include/ -I/usr/include/c++/6/ -I/usr/include/x86_64-linux-gnu/c++/6/ -I./generator_data/aosp/core/libutils/include/ -I./generator_data/aosp/libfmq/base > ./tmp/dump.js

# hisi
# python -m generator.geninterceptor ./generator_data/interceptor_data/gatekeeper.hi6250.c78bffe0c3dec2aa0f9a388c37a753b4.json > ./tmp/interceptor.js

# bullhead
# python -m generator.geninterceptor ./generator_data/interceptor_data/gatekeeper.msm8992.b12bc213d19fd23956aaa66277fde2d9.json > ./tmp/interceptor.js

# rest
# python -m generator.geninterceptor ./generator_data/interceptor_data/gatekeeper_1.0.json > ./tmp/interceptor.js

# cat ./tmp/interceptor.js ./tmp/dump.js > ./tmp/recorder_gk1_legacy.js

################################################################################
# cpp fingerprint
################################################################################

# LD_LIBRARY_PATH=. python -m generator.gendumper "BiometricsFingerprint" ./generator_data/aosp/BiometricsFingerprint.hpp -Wall -I./generator_data/aosp/libhardware/include/ -I./generator_data/aosp/core/libcutils/include/ -I./generator_data/aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ -I./generator_data/aosp/ -I./generator_data/aosp/libhidl/base/include/ -I/usr/include/c++/6/ -I/usr/include/x86_64-linux-gnu/c++/6/ -I./generator_data/aosp/core/libutils/include/ -I./generator_data/aosp/libfmq/base > ./tmp/dump.js

# python -m generator.geninterceptor ./generator_data/interceptor_data/fingerprint_2.1.json > ./tmp/interceptor.js

# cat ./tmp/interceptor.js ./tmp/dump.js > ./tmp/recorder_fp2_1.js

################################################################################
# cpp drm HIDL
################################################################################

# LD_LIBRARY_PATH=. python -m generator.gendumper "DrmPlugin" ./generator_data/aosp/DrmPlugin.hpp -Wall -I./generator_data/aosp/libhardware/include/ -I./generator_data/aosp/core/libcutils/include/ -I./generator_data/aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ -I./generator_data/aosp/ -I./generator_data/aosp/libhidl/base/include/ -I/usr/include/c++/6/ -I/usr/include/x86_64-linux-gnu/c++/6/ -I./generator_data/aosp/core/libutils/include/ -I./generator_data/aosp/libfmq/base/ -I./generator_data/aosp/core/liblog/include -I/home/dex/Code/UCSB/fuzzlet/tzzz/tzzz-hal-dumper/generator_data/aosp/frameworks/av/media/libstagefright/foundation/include > ./tmp/dump.js
# 
# python -m generator.geninterceptor ./generator_data/interceptor_data/drm_1.0.json > ./tmp/interceptor.js
# 
# cat ./tmp/interceptor.js ./tmp/dump.js > ./tmp/recorder_drm1.js

################################################################################
# cpp drm default (bullhead)
################################################################################

# LD_LIBRARY_PATH=. python -m generator.gendumper "DrmPlugin" \
#     ./generator_data/aosp/platform/frameworks/av/drm/mediadrm/plugins/clearkey/DrmPlugin.h \
#     -x c++ -Wall \
#     -I./generator_data/aosp/libhardware/include/ \
#     -I./generator_data/aosp/platform/system/core/include \
#     -I./generator_data/aosp/platform/system/libfmq/base/ \
#     -I./generator_data/aosp/platform/system/core/liblog/include \
#     -I/usr/include/c++/8/ \
#     -I/usr/include/x86_64-linux-gnu/c++/8/ \
#     -I/usr/lib/llvm-9/lib/clang/9.0.0/include/ \
#     -I./generator_data/aosp/platform/system/libhidl/base/include/ \
#     -I./generator_data/aosp/platform/frameworks/av/include \
#     -I./generator_data/aosp/platform/frameworks/av/media/libstagefright/include \
#     -I./generator_data/aosp/platform/frameworks/native/include \
#     -I./generator_data/aosp/platform/frameworks/av/drm/mediadrm/plugins/clearkey/common/include > ./tmp/dump.js
# 
# python -m generator.geninterceptor ./generator_data/interceptor_data/drm_bullhead.json > ./tmp/interceptor.js
# 
# cat ./tmp/interceptor.js ./tmp/dump.js > ./tmp/recorder_drm1_bullhead.js

################################################################################
# cleanup
################################################################################

rm ./tmp/interceptor.js ./tmp/dump.js

