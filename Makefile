MKFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
DIR := $(shell dirname $(MKFILE))

ENV_FILE ?= ./docker/envs/taimen-km.env

DOCKER := docker

DEVICE ?= 712KPBF1235565
CA ?= "android.hardware.keymaster@3.0-service.optee"
DEVICE_NAME ?= hikey620

.PHONY: build help

help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
	@$(DOCKER) compose build

run: ## Run the Docker container using entrypoint
	@$(DOCKER) compose --env-file ${ENV_FILE} run --rm \
	  --env DEVICE=$(DEVICE) \
	  teezz-recorder /docker-entrypoint.sh

mutatorgen: ## Run Docker container to generate protobuf files
	@$(DOCKER) compose --env-file ${ENV_FILE} run --rm \
	  --env DEVICE=$(DEVICE) \
	  teezz-recorder /mutatorgen-entrypoint.sh

run-sh: ## Run the Docker container and spawn shell
	@$(DOCKER) compose --env-file ${ENV_FILE} run --rm \
	  --env DEVICE=$(DEVICE) \
	  teezz-recorder "/bin/bash"

test:
	@$(DOCKER) compose run --rm \
	  teezz-recorder /test-entrypoint.sh

test_c:
	LD_LIBRARY_PATH=. python3 -m unittest generator.tests.c_test

test_cpp:
	LD_LIBRARY_PATH=. python3 -m unittest generator.tests.cpp_test

setup-dualrecord:
	npm install frida-compile

compile-js:
	rm -f $(DIR)/dualrecorder/generated/explore.js
	rmdir $(DIR)/dualrecorder/generated
	node $(DIR)/node_modules/frida-compile/bin/compile.js -o $(DIR)/dualrecorder/generated/explore.js $(DIR)/dualrecorder/dual.js

dualrecord:
	python -m dualrecorder ./dualrecorder/generated/explore.js $(CA)
