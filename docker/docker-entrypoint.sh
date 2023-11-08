#!/usr/bin/env bash

set -eu

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
/target/gen.sh

################################################################################
# Merge HAL and ioctl recorder
################################################################################

cd /root/workdir
cp /target/dual.js .
node /root/node_modules/frida-compile/bin/compile.js -o dualrec.js dual.js

################################################################################
# Get frida-server ready on device
################################################################################

# check if we can access $DEVICE, and if we have root
adb -s $DEVICE shell 'su -c pwd && su -c echo "OK"' | grep "OK"
echo "pwd $DEVICE: OK ($?)"

# check if frida-server present and push it, if not
ret=`adb -s $DEVICE shell 'ls /data/local/tmp/frida-server && echo "OK"' | grep -q "OK"; echo $?`

echo "ret is $ret"

if [ $ret -ne 0 ]; then
  adb -s $DEVICE push /root/frida-server /data/local/tmp/frida-server
  echo "push frida-server: OK ($?)"
  adb -s $DEVICE shell 'su -c chmod +x /data/local/tmp/frida-server'
fi

################################################################################
# Run dualrecord for target
################################################################################

# test runner (knows how to execute drivers)
# * vts tests (attach to system service)
# * dalvikvm tests (attach to system service)
# * custom clients (no system service we can attach to, use LD_PRELOAD to have it generic)

# run recorder (can be configured for only HAL, only ioctl, and both)

PYTHONPATH=/src python3 -m autorecord --mode both \
                /teezz-ca-driver/$CLI_TESTS \
                $DEVICE $TEE $CA /root/workdir/dualrec
