#!/usr/bin/env bash

set -eu

# change to workdir and download needed aosp repos
cd /root/workdir
/target/get_aosp.sh

# 
# TARGET=gatekeeperd
# 
# /in/targets/bullhead/gen.sh
# 
# # check if we can access $DEVICE and if we have root
# adb -s $DEVICE shell 'su -c pwd && echo "OK"' | grep "OK"
# adb -s $DEVICE push /in/frida/frida-server-14.2.7-android-arm64 /data/local/tmp/frida-server
# adb -s $DEVICE shell 'su -c chmod +x /data/local/tmp/frida-server'
# adb -s $DEVICE shell 'su -c /data/local/tmp/frida-server' &
# frida-ps -U | grep $TARGET
