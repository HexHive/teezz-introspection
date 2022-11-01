#!/usr/bin/env python
import os
import sys
import frida
import logging
import hexdump
import string
import random
import time
from queue import Queue
from threading import Thread

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


DIR = os.path.dirname(os.path.realpath(__file__))
DATADIR = os.path.join(DIR, "data")
ALNUM = list(string.ascii_letters + string.digits)
RAND_SUFFIXES = {}
DATA = {}
CURR_FUNC = None
CURR_ARG = None
Q = Queue()


class DumperCmd:
    SAVE = 's'
    QUIT = 'q'


def handle_dump_q(q, process):

    process_dir = os.path.join(DATADIR, process)
    if not os.path.isdir(process_dir):
        os.mkdir(process_dir)

    log.info("Dumps can be found in {}".format(process_dir))
    transaction_id = 0

    while True:
        elem = q.get()
        if elem == DumperCmd.SAVE:
            transaction_id += 1
            continue
        elif elem == DumperCmd.QUIT:
            return

        transaction_dir = os.path.join(process_dir, str(transaction_id))
        if not os.path.isdir(transaction_dir):
            os.mkdir(transaction_dir)

        dump = elem
        log.info("#######")

        id_dir = os.path.join(transaction_dir, str(dump['dump_id']))
        if not os.path.isdir(id_dir):
                os.mkdir(id_dir)

        # mkdir onenter
        onenter_dir = os.path.join(id_dir, "onenter")
        os.mkdir(onenter_dir)
        for k in dump['onEnter'].keys():
            file_path = os.path.join(onenter_dir, k)
            if dump['onEnter'][k]:
                with open(file_path, "wb") as f:
                    f.write(dump['onEnter'][k])

        # mkdir onleave
        onleave_dir = os.path.join(id_dir, "onleave")
        os.mkdir(onleave_dir)
        for k in dump['onLeave'].keys():
            file_path = os.path.join(onleave_dir, k)
            if dump['onLeave'][k]:
                with open(file_path, "wb") as f:
                    f.write(dump['onLeave'][k])

        log.info(dump['struct'])
        log.info(dump['time'])

        dump = None


def on_message(msg, data):

    if msg['type'] == 'error':
        # print the error mesage if we receive 'error' as type
        print(msg['stack'])
    elif msg['type'] == 'send' and 'payload' in msg:
        log.info(msg)
        dump_id = msg['payload']['dump_id']

        if dump_id not in RAND_SUFFIXES:
            random.shuffle(ALNUM)
            RAND_SUFFIXES[dump_id] = "{}_{}".format("".join(ALNUM[:10]), dump_id)
        rand_suffix = RAND_SUFFIXES[dump_id]

        if rand_suffix not in DATA:
            DATA[rand_suffix] = { }

        if 'type' in msg['payload'] and msg['payload']['type'] == 'done':
            # dumping done. send it through the Q and delete it from our dict
            Q.put(DATA[rand_suffix])
            del DATA[rand_suffix]
            del RAND_SUFFIXES[dump_id]
            return

        if msg['payload']['type'] == 'struct':
            log.info(msg['payload']['dump_id'])
            log.info(msg['payload']['name'])
            DATA[rand_suffix]['struct'] = msg['payload']['name']
            DATA[rand_suffix]['dump_id'] = dump_id
            DATA[rand_suffix]['cmd'] = msg['payload']['cmd']
            DATA[rand_suffix]['onEnter'] = {}
            DATA[rand_suffix]['onLeave'] = {}
            timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')
            DATA[rand_suffix]['time'] = timestamp
            return
        elif msg['payload']['type']:
            #log.info(msg['payload']['dump_id'])
            if msg['payload']['on_enter']:
                DATA[rand_suffix]['onEnter'][msg['payload']['type']] = data
            else:
                DATA[rand_suffix]['onLeave'][msg['payload']['type']] = data
            return


def main(js, process):

    # set up thread to persist the dumps to disk
    dumpq_worker = Thread(target=handle_dump_q, args=(Q,process))
    dumpq_worker.setDaemon(True)  # exit when main thread terminates
    dumpq_worker.start()

    # set up the frida connection to the device and target process
    device = frida.get_usb_device()
    #device = frida.get_device_manager().add_remote_device("localhost:4242")
    session = device.attach(process)

    with open(js) as f:
        script = session.create_script(f.read())

    script.on('message', on_message)
    script.load()

    log.info("Let's rock!")

    while True:
        cmd = input()
        if cmd == DumperCmd.SAVE:
            Q.put(DumperCmd.SAVE)
        elif cmd == DumperCmd.QUIT:
            # detach the target process
            session.detach()
            # tell the worker to terminate and wait for it
            Q.put(DumperCmd.QUIT)
            dumpq_worker.join()
            break
        else:
            log.info("Unknown cmd {}.".format(cmd))


def usage():
    print("{} <script.js> <daemon>\n\n"
            "Examples:\n"
            "\t{} qsee_ioctl_dump.js android.hardware.keymaster@3.0-service-qti\n"
            "\t{} tc_ioctl_dump.js android.hardware.keymaster@3.0-service\n"
            .format(sys.argv[0], sys.argv[0], sys.argv[0]))


if __name__=="__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit()
    main(sys.argv[1], sys.argv[2])
