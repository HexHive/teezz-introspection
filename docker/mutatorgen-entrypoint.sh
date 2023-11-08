#!/usr/bin/env bash

set -eu

/bin/bash

mkdir -p /root/workdir/aosp

################################################################################
# Get the source code
################################################################################

# change to workdir and download needed aosp repos
cd /root/workdir/aosp
/target/get_aosp.sh

################################################################################
# Generate HAL DBII recorder
################################################################################

cd /root/workdir
/target/gen_mutator.sh
