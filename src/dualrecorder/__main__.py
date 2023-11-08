import os
import string
import argparse
import frida
import time
import random
import hexdump
import pickle
import errno
from haldump import dump
from fridadumper import ioctldumper
from queue import Queue
from threading import Thread
import sys
import logging

################################################################################
# LOGGING
################################################################################

FORMAT = (
    "%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s"
)
logging.basicConfig(
    stream=sys.stdout,
    format=FORMAT,
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.DEBUG,
)
log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

ALNUM = list(string.ascii_letters + string.digits)
DATA_KEYS = {}
DATA = {}
HIGHLVL_ID = 0
Q = Queue()

################################################################################
# CODE
################################################################################

class DumperCmd:
    SAVE = "s"
    QUIT = "q"


# thx https://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def handle_dump_q(q, ca, out_dir):

    process_dir = os.path.join(out_dir, ca)
    if not os.path.isdir(process_dir):
        mkdir_p(process_dir)

    log.info("Dumps can be found in {}".format(process_dir))
    sequence_id = 0

    while True:
        qentry = q.get()
        # log.info(f"Receive qentry: {qentry}")
        if qentry == DumperCmd.SAVE:
            sequence_id += 1
            continue
        elif qentry == DumperCmd.QUIT:
            return
        elif isinstance(qentry, dict):
            high_lvl_id = dump.get_high_lvl_id()
            if "ctx_closed" in qentry:
                dump.store_recording(
                    qentry, sequence_id, process_dir, high_lvl_id
                )
            else:
                ioctldumper.store_recording(qentry, sequence_id, process_dir, high_lvl_id)


def on_message(msg, data):

    if msg["type"] == "error":
        # print the error mesage if we receive 'error' as type
        print(msg["stack"])
    elif msg["type"] == "send" and "payload" in msg:
        log.info(msg)
        if "lvl" in msg["payload"] and msg["payload"]["lvl"] == "high":
            dump.on_message(msg, data)
        else:
            ioctldumper.on_message(msg, data)
    else:
        # what is this?
        import ipdb

        ipdb.set_trace()


def main(dbii_js, ca, out_dir):

    dump.Q = Q
    ioctldumper.Q = Q
    # set up thread to persist the dumps to disk
    dumpq_worker = Thread(target=handle_dump_q, args=(Q, ca, out_dir))
    dumpq_worker.setDaemon(True)  # exit when main thread terminates
    dumpq_worker.start()

    # set up the frida connection to the device and target process
    device = frida.get_usb_device()
    # device = frida.get_device_manager().add_remote_device("localhost:4242")
    session = device.attach(ca)

    with open(dbii_js) as f:
        script = session.create_script(f.read())

    script.on("message", on_message)
    script.load()

    log.info("Let's rock!")

    while True:
        cmd = input()
        if cmd == DumperCmd.SAVE:
            Q.put(DumperCmd.SAVE)
        elif cmd == DumperCmd.QUIT:
            # tell the worker to terminate and wait for it
            Q.put(DumperCmd.QUIT)
            dumpq_worker.join()
            log.info("We're done here!")
            # detach the target process
            session.detach()
            break
        else:
            log.info("Unknown cmd {}.".format(cmd))


def setup_args():

    parser = argparse.ArgumentParser()
    parser.add_argument("dbii_js", help="DBII recorder script.")
    parser.add_argument(
        "ca",
        help="Client application hooked to observe interaction"
        " with trusted application.",
    )
    parser.add_argument("out_dir", help="Output directory for recordings.")
    return parser


if __name__ == "__main__":
    arg_parser = setup_args()
    args = arg_parser.parse_args()
    main(args.dbii_js, args.ca, args.out_dir)
