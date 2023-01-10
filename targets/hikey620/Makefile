MKFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
DIR := $(shell dirname $(MKFILE))

DEVICE = 025757ea3c90aa91
CA = "android.hardware.keymaster@3.0-service.optee"
DEVICE_NAME= "hikey620"

.PHONY: build help

help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

compile-js: generate_haldump-js
	rm -rf dualrecord-js/
	node /src/node_modules/frida-compile/bin/compile.js -o dualrecord-js/explore.js dual.js

dualrecord:
	python -m dualrecorder ./dualrecorder/generated/explore.js $(CA)

setup: ## Download AOSP for given device
	cd /targets/$(DEVICE_NAME)/ && ./get_aosp.sh

generate_interfaces:
	cd /targets/$(DEVICE_NAME)/aosp && \
	prebuilts/build-tools/linux-x86/bin/hidl-gen -o ../generated_interfaces -L c++-headers -randroid.hardware:hardware/interfaces -randroid.hidl:system/libhidl/transport android.hardware.keymaster@3.0 && \
	prebuilts/build-tools/linux-x86/bin/hidl-gen -o ../generated_interfaces -L c++-headers -randroid.hardware:hardware/interfaces -randroid.hidl:system/libhidl/transport android.hidl.base@1.0 && \
	prebuilts/build-tools/linux-x86/bin/hidl-gen -o ../generated_interfaces -L c++-headers -randroid.hardware:hardware/interfaces -randroid.hidl:system/libhidl/transport android.hidl.manager@1.0

generate_haldump-js: generate_interfaces
	mkdir -p generated
	python3 -m generator.geninterceptor /targets/hikey620/keystore.hi6250.355fcb92f2820b04f9530837a9cc1d9c.json > generated/1.js
	python3.6 -m generator.gendumper "OpteeKeymaster3Device" /targets/hikey620/aosp/external/optee/apps/keymaster/include/optee_keymaster/optee_keymaster3_device.h -I/targets/hikey620/aosp/external/optee/apps/keymaster/include/ -I/targets/hikey620/generated_interfaces/ -I/targets/hikey620/aosp/system/libhidl/base/include/  -I/targets/hikey620/aosp/system/core/libcutils/include/  -I/targets/hikey620/aosp/system/core/libutils/include/  -I/targets/hikey620/aosp/system/libfmq/base/ -I/targets/hikey620/aosp/external/apps/keymaster/include/ -I/targets/hikey620/aosp/system/keymaster/include  -I/targets/hikey620/aosp/hardware/libhardware/include/ -std=c++17 -xc++ > generated/2.js
	cd generated && cat 1.js 2.js > hal.js && rm 1.js 2.js

haldump: generate_haldump-js
	python3 -m haldump android.hardware.keymaster@3.0-service.optee generated/hal.js
ioctl:
	python3 -m fridadumper /targets/hikey620/ioctl.js $(CA)
dual-record: compile-js
	python3 -m dualrecorder dualrecord-js/explore.js $(CA)
