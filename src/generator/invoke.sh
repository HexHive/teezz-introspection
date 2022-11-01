#!/usr/bin/env bash

### keymaster
LD_LIBRARY_PATH=. python -- ./gen_dumper.py "struct keymaster1_device" ./km.hpp -Wall -I./aosp/libhardware/include/ -I./aosp/core/libcutils/include/ -I./aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ > ./generated/keystore_hal_dump_gen.js

# qsee
./gen_interceptor.py ./hal_interceptor_data/keystore.msm8992.023b83490da540a3fe637be86d62fb95.json > ./generated/keystore_hal_interceptor_msm8922_gen.js
cat ./generated/keystore_hal_interceptor_msm8922_gen.js ./generated/keystore_hal_dump_gen.js > ./generated/keystore_hal_msm8922_gen.js

# tc
./gen_interceptor.py ./hal_interceptor_data/keystore.hi6250.304f85a1316b7920544162a56f076837.json > ./generated/keystore_hal_interceptor_hi6250_gen.js
cat ./generated/keystore_hal_interceptor_hi6250_gen.js ./generated/keystore_hal_dump_gen.js > ./generated/keystore_hal_hi6250_gen.js


### gatekeeper
LD_LIBRARY_PATH=. python -- ./gen_dumper.py "struct gatekeeper_device" ./gk.hpp -Wall -I./aosp/libhardware/include/ -I./aosp/core/libcutils/include/ -I./aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ > ./generated/gatekeeper_hal_dump_gen.js

# qsee
./gen_interceptor.py ./hal_interceptor_data/gatekeeper.msm8992.b12bc213d19fd23956aaa66277fde2d9.json > ./generated/gatekeeper_hal_interceptor_msm8922_gen.js
cat ./generated/gatekeeper_hal_interceptor_msm8922_gen.js ./generated/gatekeeper_hal_dump_gen.js > ./generated/gatekeeper_hal_msm8922_gen.js

# tc
./gen_interceptor.py ./hal_interceptor_data/gatekeeper.hi6250.c78bffe0c3dec2aa0f9a388c37a753b4.json > ./generated/gatekeeper_hal_interceptor_hi6250_gen.js
cat ./generated/gatekeeper_hal_interceptor_hi6250_gen.js ./generated/gatekeeper_hal_dump_gen.js > ./generated/gatekeeper_hal_hi6250_gen.js

### fingerprintd
LD_LIBRARY_PATH=. python -- ./gen_dumper.py "struct fingerprint_device" ./fp.hpp -Wall -I./aosp/libhardware/include/ -I./aosp/core/libcutils/include/ -I./aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ > ./generated/fingerprint_hal_dump_gen.js

# qsee
./gen_interceptor.py ./hal_interceptor_data/fingerprint.msm8992.9e4b739c7a8e4451a551f4bce3fcd53c.json > generated/fingerprint_hal_interceptor_msm8922_gen.js
cat ./generated/fingerprint_hal_interceptor_msm8922_gen.js ./generated/fingerprint_hal_dump_gen.js > ./generated/fingerprint_hal_msm8922_gen.js

# tc
./gen_interceptor.py ./hal_interceptor_data/fingerprint.hi6250.8e0189cacef399dd107afaa66fa595e4.json > ./generated/fingerprint_hal_interceptor_hi6250_gen.js
cat ./generated/fingerprint_hal_interceptor_hi6250_gen.js ./generated/fingerprint_hal_dump_gen.js > ./generated/fingerprint_hal_hi6250_gen.js

# cpp dumping (in progress)
#LD_LIBRARY_PATH=. python -- ./cpp.py "KeymasterDevice" ./aosp/KeymasterDevice.hpp -Wall -I./aosp/libhardware/include/ -I./aosp/core/libcutils/include/ -I./aosp/core/libsystem/include/ -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/ -I./aosp/ -I./aosp/libhidl/base/include/ -I/usr/include/c++/6/ -I/usr/include/x86_64-linux-gnu/c++/6/ -I./aosp/core/libutils/include/ -I./aosp/libfmq/base/
