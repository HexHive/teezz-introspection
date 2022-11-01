#!/usr/bin/env python
import os
import sys
import frida
import logging
import hexdump
import time
import string
import random
import struct
import pickle

ALNUM = list(string.ascii_letters + string.digits)

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
#log.setLevel(logging.ERROR)

DUMP_DIR0 = os.path.abspath("./data/")
DATA = {}

RAND_SUFFIXES = {}
DATA = {}
CURR_FUNC = None
CURR_ARG = None


def on_message(msg, data):

    if msg['type'] == 'error':
        print(msg['stack'])
    elif msg['type'] == 'send' and 'payload' in msg:
        payload = msg['payload']
        if payload['type'] == 'init_dump':
            log.info(msg)
        elif payload['type'] == 'dump':
            log.info(msg)
            if data:
                hexdump.hexdump(data)


def main(daemon, dumperjs):

    device = frida.get_usb_device()
    session = device.attach(daemon)

    with open(dumperjs) as f:
        script = session.create_script(f.read())

    script.on('message', on_message)
    script.load()

    log.info("Let's rock!")

    input()
    session.detach()


def usage():
    print("{0} <daemon> <dumper.js>\n\ne.g.\n\t{0} keystore keystore_hal_msm8922_gen.js".format(sys.argv[0]))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit()
    main(sys.argv[1], sys.argv[2])
