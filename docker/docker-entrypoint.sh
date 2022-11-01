#!/usr/bin/env bash

set -eu

TARGET=gatekeeperd

/in/targets/bullhead/gen.sh

# check if we can access $DEVICE and if we have root
adb -s $DEVICE shell 'su -c pwd && echo "OK"' | grep "OK"
adb -s $DEVICE push /in/frida/frida-server-14.2.7-android-arm64 /data/local/tmp/frida-server
adb -s $DEVICE shell 'su -c chmod +x /data/local/tmp/frida-server'
adb -s $DEVICE shell 'su -c /data/local/tmp/frida-server' &
frida-ps -U | grep $TARGET


# setup gatekeeper tests
adb -s $DEVICE push /in/targets/bullhead/gatekeeperd-unit-tests /data/local/tmp/

for test in `cat /in/targets/bullhead/gk_tests.txt`;
do
  echo $test;
  adb -s $DEVICE shell "su -c /data/local/tmp/gatekeeperd-unit-tests --gtest_filter=$test";
done
