import os
import sys
import frida
import logging
import hexdump
import time
import string
import random
import pickle

ALNUM = list(string.ascii_letters + string.digits)

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
# log.setLevel(logging.ERROR)

DIR = os.path.dirname(os.path.realpath(__file__))
DUMP_DIR = os.path.join(DIR, "data")

RAND_SUFFIXES = {}
DATA = {}
CURR_FUNC = None
CURR_ARG = None


def on_message(msg, data):

    if msg["type"] == "error":
        print(msg["stack"])
    elif msg["type"] == "send" and "payload" in msg:
        log.info(msg)
        dump_id = msg["payload"]["dump_id"]
        if dump_id not in RAND_SUFFIXES:
            random.shuffle(ALNUM)
            RAND_SUFFIXES[dump_id] = "{}_{}".format(
                "".join(ALNUM[:10]), dump_id
            )

        rand_suffix = RAND_SUFFIXES[dump_id]
        if rand_suffix not in DATA:
            DATA[rand_suffix] = {}

        if msg["payload"]["type"] == "init_dump":
            log.info(msg["payload"]["dump_id"])
            DATA[rand_suffix]["func"] = msg["payload"]["func"]
            DATA[rand_suffix]["onEnter"] = {"params": {}}
            DATA[rand_suffix]["onLeave"] = {"params": {}}
            DATA[rand_suffix]["dump_id"] = dump_id
            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
            DATA[rand_suffix]["time"] = timestamp
        elif msg["payload"]["type"] == "dump":
            # log.info(msg['payload']['dump_id'])

            # if we do not have data for this parameter, we do not save it
            if not data:
                return

            log.info(hexdump.hexdump(data))
            arg_data = (msg["payload"]["param_type"], data)

            if msg["payload"]["on_enter"]:
                if (
                    msg["payload"]["param"]
                    not in DATA[rand_suffix]["onEnter"]["params"]
                ):
                    DATA[rand_suffix]["onEnter"]["params"][
                        msg["payload"]["param"]
                    ] = []
                DATA[rand_suffix]["onEnter"]["params"][
                    msg["payload"]["param"]
                ].append(arg_data)
            else:
                if (
                    msg["payload"]["param"]
                    not in DATA[rand_suffix]["onLeave"]["params"]
                ):
                    DATA[rand_suffix]["onLeave"]["params"][
                        msg["payload"]["param"]
                    ] = []
                DATA[rand_suffix]["onLeave"]["params"][
                    msg["payload"]["param"]
                ].append(arg_data)
        elif msg["payload"]["type"] == "fini_dump":
            # onleave of recording finished
            pass
        else:
            log.error("What's this?")
            import ipdb

            ipdb.set_trace()


def main(daemon, dumperjs):

    device = frida.get_usb_device()
    session = device.attach(daemon)

    with open(dumperjs) as f:
        script = session.create_script(f.read())

    script.on("message", on_message)
    script.load()

    log.info("Let's rock!")
    user_input = input()
    print(f"received {user_input}")

    # print(DATA)
    print(f"Writing data to {DUMP_DIR}")

    if not os.path.isdir(DUMP_DIR):
        os.mkdir(DUMP_DIR)

    for rand_suffix in DATA.keys():
        # log.info(DATA[rand_suffix])
        log.info("#######")

        func_dir = os.path.join(
            DUMP_DIR,
            "{}_{}".format(
                DATA[rand_suffix]["func"], str(DATA[rand_suffix]["dump_id"])
            ),
        )
        if not os.path.isdir(func_dir):
            os.mkdir(func_dir)

        # mkdir onenter
        onenter_dir = os.path.join(func_dir, "onenter")
        os.mkdir(onenter_dir)
        for arg in DATA[rand_suffix]["onEnter"]["params"].keys():
            file_path = os.path.join(onenter_dir, arg)
            if DATA[rand_suffix]["onEnter"]["params"][arg]:
                with open(file_path, "wb") as f:
                    pickle.dump(DATA[rand_suffix]["onEnter"]["params"][arg], f)

        # mkdir onleave
        onleave_dir = os.path.join(func_dir, "onleave")
        os.mkdir(onleave_dir)
        for arg in DATA[rand_suffix]["onLeave"]["params"].keys():
            file_path = os.path.join(onleave_dir, arg)
            if DATA[rand_suffix]["onLeave"]["params"][arg]:
                with open(file_path, "wb") as f:
                    pickle.dump(DATA[rand_suffix]["onLeave"]["params"][arg], f)

        log.info(DATA[rand_suffix]["func"])
        log.info(DATA[rand_suffix]["time"])

    session.detach()
