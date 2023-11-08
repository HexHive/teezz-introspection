import os
import sys
import frida
import logging
import hexdump
import string
import errno
import time
from queue import Queue
from threading import Thread

################################################################################
# LOGGING
################################################################################

log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

DIR = os.path.dirname(os.path.realpath(__file__))
ALNUM = list(string.ascii_letters + string.digits)
RAND_SUFFIXES = {}
DATA = {}
CURR_FUNC = None
CURR_ARG = None
Q = Queue()

JS = {
    "qsee": {"script": os.path.join(DIR, "qsee", "qsee_ioctl_dump.js")},
    "optee": {"script": os.path.join(DIR, "optee", "optee_ioctl_dump.js")},
    "tc": {"script": os.path.join(DIR, "tc", "tc_ioctl_dump.js")},
}

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


def store_recording(dump, seqid, procdir, high_lvl_id):

    transaction_dir = os.path.join(procdir, str(seqid), str(high_lvl_id))
    if not os.path.isdir(transaction_dir):
        mkdir_p(transaction_dir)

    log.info("#######")

    id_dir = os.path.join(transaction_dir, f"ioctl_{dump['dump_id']}")
    if not os.path.isdir(id_dir):
        os.mkdir(id_dir)

    # mkdir onenter
    onenter_dir = os.path.join(id_dir, "onenter")
    os.mkdir(onenter_dir)
    # log.info(dump)
    for k in dump["onEnter"].keys():
        file_path = os.path.join(onenter_dir, k)
        if dump["onEnter"][k]:
            with open(file_path, "wb") as f:
                f.write(dump["onEnter"][k])

    # mkdir onleave
    onleave_dir = os.path.join(id_dir, "onleave")
    os.mkdir(onleave_dir)
    for k in dump["onLeave"].keys():
        file_path = os.path.join(onleave_dir, k)
        if dump["onLeave"][k]:
            with open(file_path, "wb") as f:
                f.write(dump["onLeave"][k])

    log.info(dump["struct"])
    log.info(dump["time"])

    dump = None


def handle_dump_q(q: Queue, ca: str, out_dir: str):

    process_dir = os.path.join(out_dir, ca)
    if not os.path.isdir(process_dir):
        mkdir_p(process_dir)

    log.info("Dumps can be found in {}".format(process_dir))

    sequence_id = 0

    while True:
        elem = q.get()
        if elem == DumperCmd.SAVE:
            sequence_id += 1
            continue
        elif elem == DumperCmd.QUIT:
            return

        store_recording(elem, sequence_id, process_dir)


def on_message(msg, data):

    if msg["type"] == "error":
        # print the error mesage if we receive 'error' as type
        print(msg["stack"])
    elif msg["type"] == "send" and "payload" in msg:
        log.info(msg)
        dump_id = msg["payload"]["dump_id"]

        if dump_id not in DATA:
            DATA[dump_id] = {}

        # convinience variable
        dump = DATA[dump_id]

        if "type" in msg["payload"] and msg["payload"]["type"] == "done":
            # dumping done. send it through the Q and delete it from our dict
            Q.put(DATA[dump_id])
            del DATA[dump_id]
            return

        if msg["payload"]["type"] == "struct":
            log.info(msg["payload"]["dump_id"])
            log.info(msg["payload"]["name"])
            dump["struct"] = msg["payload"]["name"]
            dump["dump_id"] = dump_id
            dump["cmd"] = msg["payload"]["cmd"]
            dump["onEnter"] = {}
            dump["onLeave"] = {}
            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
            dump["time"] = timestamp
            return
        elif msg["payload"]["type"]:
            # log.info(msg['payload']['dump_id'])
            if msg["payload"]["on_enter"]:
                dump["onEnter"][msg["payload"]["type"]] = data
            else:
                dump["onLeave"][msg["payload"]["type"]] = data
            return


def main(tee: str, ca: str, out_dir: str):

    # create output dir if not exists
    if not os.path.isdir(out_dir):
        os.mkdir(out_dir)

    # set up thread to persist the dumps to disk
    dumpq_worker = Thread(target=handle_dump_q, args=(Q, ca, out_dir))
    dumpq_worker.setDaemon(True)  # exit when main thread terminates
    dumpq_worker.start()

    # set up the frida connection to the device and target process
    device = frida.get_usb_device()
    # device = frida.get_device_manager().add_remote_device("localhost:4242")
    try:
        session = device.attach(ca)
    except frida.TransportError as e:
        log.error(e)
        sys.exit()

    with open(JS[tee]["script"]) as f:
        source = f.read()
        script = session.create_script(source)

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


