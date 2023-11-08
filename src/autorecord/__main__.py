import argparse
import time
import logging
import os
import fcntl
import subprocess
import select

from adb import adb

from typing import Type


FORMAT = (
    "%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s"
)
logging.basicConfig(
    format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG
)
log = logging.getLogger(__name__)

DBII_JS = "/root/workdir/recorder.js"
DUALREC_JS = "/root/workdir/dualrec.js"


def fridaserver(device_id: str):
    while True:
        try:
            cmd = "pkill -9 frida-server"
            out, err = adb.execute_privileged_command(cmd, device_id)
            cmd = "pkill -l 9 frida-server"
            out, err = adb.execute_privileged_command(cmd, device_id)
        except Exception as e:
            log.error(e)
            import ipdb

            ipdb.set_trace()

        time.sleep(5)
        cmd = "/data/local/tmp/frida-server -D"
        p = adb.subprocess_privileged(cmd, device_id)

        time.sleep(3)
        poll_obj = select.poll()
        poll_obj.register(p.stdout, select.POLLIN)
        poll_res = poll_obj.poll(0)

        if poll_res:
            line = p.stdout.readline()
            log.info(f"poll_res read: {line}")
            if b"Unable to start" in line:
                print(line)
            elif not line:
                break
        else:
            break

        time.sleep(3)
        p.terminate()

    p.terminate()


def ioctl_record(tee: str, ca: str, out_dir: str) -> Type[subprocess.Popen]:
    cmd = ["python3", "-m", "fridadumper", tee, ca, out_dir],
    log.debug(f"cmd is {' '.join(cmd)}")
    p = subprocess.Popen(
        cmd,
        shell=False,
        bufsize=0,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return p


def dbii_record(dbii_js: str, ca: str, out_dir: str) -> Type[subprocess.Popen]:
    cmd = ["python3", "-m", "haldump", dbii_js, ca, out_dir]
    log.debug(f"cmd is {' '.join(cmd)}")
    p = subprocess.Popen(
        cmd,
        shell=False,
        bufsize=0,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return p


def dual_record(dbii_js: str, ca: str, out_dir: str) -> Type[subprocess.Popen]:
    cmd = ["python3", "-m", "dualrecorder", DUALREC_JS, ca, out_dir]
    log.debug(f"cmd is {' '.join(cmd)}")
    p = subprocess.Popen(
        cmd,
        shell=False,
        bufsize=0,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return p


def exec_test(
    device_id: str, mode: str, tee: str, ca: str, test_cmd: str, out_dir: str
):

    log.info("Rebooting...")
    adb.reboot(device_id)
    if adb.is_device_ready(device_id):
        log.info("Device ready, recording now.")
    else:
        import ipdb

        ipdb.set_trace()

    fridaserver(device_id)
    if mode == "ioctl":
        recorder_p = ioctl_record(tee, ca, out_dir)
    elif mode == "hal":
        recorder_p = dbii_record(DBII_JS, ca, out_dir)
    else:
        recorder_p = dual_record(DUALREC_JS, ca, out_dir)

    # get polling object, which supports registering and unregistering file
    # descriptors, pollable for I/O events
    poll_out = select.poll()

    # get fd of stdout
    out_fd = recorder_p.stdout.fileno()
    # get file access mode and status flags
    out_fl = fcntl.fcntl(out_fd, fcntl.F_GETFL)
    # set file non-blocking
    fcntl.fcntl(out_fd, fcntl.F_SETFL, out_fl | os.O_NONBLOCK)

    # register an fd with the polling object, so that future `poll()` calls can
    # check for pending i/o events
    poll_out.register(recorder_p.stdout, select.POLLIN)

    while True:
        # check if we got some events on stdout
        out_poll_res = poll_out.poll(0)
        if out_poll_res:
            line = recorder_p.stdout.readline()
            print(line)
            if b"Let's rock" in line:
                break
            elif b"ERROR" in line:
                import ipdb

                ipdb.set_trace()
            elif not line:
                print("waiting for recorder_p")
                time.sleep(2)
        else:
            print("waiting for recorder_p")
            time.sleep(2)

    ############################################################################
    # run test
    ############################################################################

    adb_p = adb.subprocess_privileged(test_cmd, device_id)

    while adb_p.poll() is None:
        print("waiting for adb_p")
        time.sleep(5)

    log.info(f"adb_p exited with {adb_p.poll()}")

    ############################################################################
    # recorder
    ############################################################################

    while True:
        out_poll_res = poll_out.poll(0)
        if out_poll_res:
            try:
                line = recorder_p.stdout.readline()
            except OSError:
                continue
            if line:
                print(line)
            if b"We're done here!" in line:
                break
        else:
            recorder_p.stdin.write(b"q\n")

    # cleanup
    recorder_p.stdin.close()
    recorder_p.stdout.close()
    recorder_p.terminate()

    adb_p.stdin.close()
    adb_p.stdout.close()
    adb_p.terminate()


def main(
    cli_tests: str, device_id: str, tee: str, ca: str, mode: str, out_dir: str
):

    with open(cli_tests, "r") as f:
        test_cmds = [cmd for cmd in f.read().split("\n") if cmd]

    if not os.path.isdir(out_dir):
        os.mkdir(out_dir)

    for idx, test_cmd in enumerate(test_cmds):
        log.info(f"test cmd: {test_cmd}")
        test_out_dir: str = os.path.join(out_dir, str(idx))
        exec_test(device_id, mode, tee, ca, test_cmd, test_out_dir)


def setup_args():
    parser = argparse.ArgumentParser()

    # add positional arguments
    parser.add_argument(
        "cli_tests", help="Newline separated list of cli commands for tests"
    )
    parser.add_argument("device_id", help="Android device id (adb devices).")
    parser.add_argument(
        "tee",
        nargs="?",
        choices=["qsee", "optee", "tc"],
        help="Trusted execution environment we are targeting.",
    )
    parser.add_argument(
        "client_application",
        help="Client application hooked to observe interaction"
        " with trusted application.",
    )
    parser.add_argument("out_dir", help="Output direcotry.")

    parser.add_argument(
        "--mode",
        default="both",
        const="all",
        nargs="?",
        choices=["ioctl", "hal", "both"],
        help="Recording mode. Records ioctl layer, hal layer, "
        "or both (default: %(default)s)",
    )
    return parser


if __name__ == "__main__":
    arg_parser = setup_args()
    args = arg_parser.parse_args()

    main(
        args.cli_tests,
        args.device_id,
        args.tee,
        args.client_application,
        args.mode,
        args.out_dir,
    )
