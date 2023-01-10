MKFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
DIR := $(shell dirname $(MKFILE))
DOCKER := docker

DEVICE ?= 025757ea3c90aa91
CA ?= "android.hardware.keymaster@3.0-service.optee"
DEVICE_NAME= "hikey620"

.PHONY: build help

help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
	@$(DOCKER) compose build

run-sh: ## Run the Docker container(s) and spawn a shell
	@$(DOCKER) compose run --rm --env DEVICE=$(DEVICE) teezz-recorder "/bin/bash"

test: test_c test_cpp

test_c:
	LD_LIBRARY_PATH=. python3 -m unittest generator.tests.c_test

test_cpp:
	LD_LIBRARY_PATH=. python3 -m unittest generator.tests.cpp_test

setup-dualrecord:
	npm install frida-compile

compile-js:
	#rm -f $(DIR)/dualrecorder/generated/explore.js
	#rmdir $(DIR)/dualrecorder/generated
	node node_modules/frida-compile/bin/compile.js -o dualrecorder/generated/explore.js dualrecorder/dual.js

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
	cd /src/
	mkdir -p generated
	python3 generator/geninterceptor.py /targets/hikey620/keystore.hi6250.355fcb92f2820b04f9530837a9cc1d9c.json > generated/1.js
	python3.6 -m generator.gendumper "OpteeKeymaster3Device" /targets/hikey620/aosp/external/optee/apps/keymaster/include/optee_keymaster/optee_keymaster3_device.h -I/targets/hikey620/aosp/external/optee/apps/keymaster/include/ -I/targets/hikey620/generated_interfaces/ -I/targets/hikey620/aosp/system/libhidl/base/include/  -I/targets/hikey620/aosp/system/core/libcutils/include/  -I/targets/hikey620/aosp/system/core/libutils/include/  -I/targets/hikey620/aosp/system/libfmq/base/ -I/targets/hikey620/aosp/external/apps/keymaster/include/ -I/targets/hikey620/aosp/system/keymaster/include  -I/targets/hikey620/aosp/hardware/libhardware/include/ -std=c++17 -xc++ > generated/2.js
	cd generated && cat 1.js 2.js > hal.js && rm 1.js 2.js
haldump: generate_haldump-js
	python3 -m haldump android.hardware.keymaster@3.0-service.optee generated/hal.js
