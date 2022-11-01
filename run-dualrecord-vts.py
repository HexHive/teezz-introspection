#!/usr/bin/env python3
import sys
import os
import fcntl
import subprocess
import shutil
import time
import logging
import select

from adb import adb

FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s " \
         "[%(filename)s:%(lineno)d] %(message)s"
logging.basicConfig(format=FORMAT,
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)

log = logging.getLogger(__name__)

DIR = os.path.dirname(os.path.realpath(__file__))
DUMP_DIR = os.path.join(DIR, "dualrecorder", "data")


def fridaserver(device_id):
    nretry = 0
    while True:
        try:
            cmd = "pkill -{} frida-server".format(15 if nretry < 3 else 9)
            out, err = adb.execute_privileged_command(cmd, device_id)
        except:
            pass

        time.sleep(3)
        cmd = "/data/local/tmp/frida-server -D"
        p = adb.subprocess_privileged(cmd, device_id)
        time.sleep(3)
        poll_obj = select.poll()
        poll_obj.register(p.stdout, select.POLLIN)
        poll_res = poll_obj.poll(0)

        if poll_res:
            line = p.stdout.readline()
            if b"Unable to start" in line:
                nretry += 1
                print(line)
        else:
            break

        time.sleep(3)
        p.terminate()

    p.terminate()


def adb_exec_test(device_id, test):
    cmd = f"LD_LIBRARY_PATH=/data/local/tmp/vtslibs/ /data/local/tmp/VtsHalKeymasterV3_0TargetTest --gtest_filter={test} 2>&1 1>/dev/null"
    p = adb.subprocess_privileged(cmd, device_id)
    return p


def dualrecorder(target):
    p = subprocess.Popen([
        f"{DIR}/.venv/bin/python", "-m", "dualrecorder",
        "./dualrecorder/generated/explore.js", target
    ],
                         shell=False,
                         bufsize=0,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    return p


def record(device_id, test, target):
    fridaserver(device_id)
    dualrecorder_p = dualrecorder(target)
    poll_obj = select.poll()
    fd = dualrecorder_p.stdout.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    poll_obj.register(dualrecorder_p.stdout, select.POLLIN)

    while True:
        poll_res = poll_obj.poll(0)
        if poll_res:
            line = dualrecorder_p.stdout.readline()
            if b"Let's rock" in line:
                break
        else:
            print("waiting for dualrecorder_p")
            time.sleep(2)

    adb_p = adb_exec_test(device_id, test)

    while adb_p.poll() is None:
        print("waiting for adb_p")
        time.sleep(5)

    #if adb_p.poll() != 0:
    #    log.error(f"adb_p exited with {adb_p.poll()}")
    #    return

    while True:
        poll_res = poll_obj.poll(0)
        if poll_res:
            try:
                line = dualrecorder_p.stdout.readline()
            except OSError:
                continue
            if line:
                print(line)
            if b"We're done here!" in line:
                break
        else:
            dualrecorder_p.stdin.write(b"q\n")

    # cleanup
    dualrecorder_p.stdin.close()
    dualrecorder_p.stdout.close()
    dualrecorder_p.terminate()

    adb_p.stdin.close()
    adb_p.stdout.close()
    adb_p.terminate()


def main(device_id, target):

    with open(f"{DIR}/available_tests.txt", "r") as f:
        tests = f.read()

    dst_dir = f"/tmp/{target}-recording"
    if not os.path.isdir(dst_dir):
        os.mkdir(dst_dir)

    log.info(f"destination dir: {dst_dir}")
    for test in tests.split("\n"):
        if not test:
            continue

        log.info(f"Testcase: {test}")

        log.info("Rebooting...")
        adb.reboot(device_id)
        if adb.is_device_ready(device_id):
            log.info("Device ready, recording now.")
            record(device_id, test, target)
        else:
            import ipdb
            ipdb.set_trace()
        src = os.path.join(DUMP_DIR, target)
        dst = os.path.join(dst_dir, test)
        shutil.move(src, dst)


def usage():
    print(f"{sys.argv[0]} <device_id> <target>")
    print("e.g.")
    print(
        f"\t{sys.argv[0]} 9WVDU18B06004395 android.hardware.keymaster@3.0-service.optee"
    )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit()
    device_id = sys.argv[1]
    target = sys.argv[2]
    main(device_id, target)
