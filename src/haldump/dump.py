import os
import frida
import logging
import hexdump

import errno
import time
import string
from pprint import pprint
import pickle
from collections import OrderedDict
from queue import Queue
from threading import Thread

################################################################################
# LOGGING
################################################################################

log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

ALNUM = list(string.ascii_letters + string.digits)
RAND_SUFFIXES = {}
DATA = {}
CURR_FUNC = None
CURR_ARG = None
Q = Queue()
HIGHLVL_ID = 0

################################################################################
# CODE
################################################################################


class RecordingException(Exception):
    pass


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


def handle_send_message(msg, data):
    log.info(msg)

    if "payload" not in msg:
        raise RecordingException("Could not find 'payload' in message.")

    # get the payload from `msg`
    payload = msg["payload"]

    # get the ID of this dump
    dump_id = payload["dump_id"]

    # the message type determines the handler for this dump
    msg_type = payload["type"]

    # create dump entry if it does not exit yet
    if dump_id not in DATA:
        DATA[dump_id] = {}
    elif msg_type == "open_func_ctx":
        raise RecordingException(
            f"Function context for dump_id {dump_id} already exists."
        )

    # `dump` is the convenience var used as a container for remote's data
    dump = DATA[dump_id]

    if "ctx_closed" in dump and dump["ctx_closed"] == True:
        raise RecordingException(
            f"Function context for dump_id {dump_id} already closed."
        )

    if msg_type == "open_func_ctx":
        log.info(msg["payload"]["dump_id"])
        dump["func"] = payload["func"]
        dump["onEnter"] = {"params": {}}
        dump["onLeave"] = {"params": {}}
        dump["dump_id"] = dump_id
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        dump["time"] = timestamp
        # indicate that remote did not close this context yet
        dump["ctx_closed"] = False
    elif msg_type == "close_func_ctx":
        dump["ctx_closed"] = True
        # dumping done. send it through the Q and delete it from our dict
        Q.put(DATA[dump_id])
        del DATA[dump_id]
    elif msg_type == "open_arg_ctx":
        # open the context for one function argument
        # all succeeding messages should be related to this argument until
        # a `close_arg_ctx` is received
        func_name = payload["func_name"]
        param_name = payload["param_name"]
        param_type = payload["param_type"]
        is_onenter = payload["on_enter"]

        hook = "onEnter" if is_onenter else "onLeave"
        params = dump[hook]["params"]

        if param_name in params:
            raise RecordingException(f"{param_name} already exists")

        params[param_name] = {
            "type": param_type,
            "ctx_closed": False,
        }

    elif msg_type == "close_arg_ctx":
        param_name = payload["param_name"]
        is_onenter = payload["on_enter"]
        hook = "onEnter" if is_onenter else "onLeave"
        params = dump[hook]["params"]
        params[param_name]["ctx_closed"] = True

    elif msg_type == "open_record_ctx":
        # remote indicates that the next couple of messages will be a record

        param_name = payload["param_name"]
        parent = payload["parent"]
        record_type = payload["record_type"]
        is_onenter = payload["on_enter"]

        hook = "onEnter" if is_onenter else "onLeave"
        param = dump[hook]["params"][param_name]

        if "nesting" in param:
            # this is a nested record
            nested_elem = param
            for nested_elem_key in param["nesting"]:
                nested_elem = nested_elem["data"][nested_elem_key]

            nested_elem["type"] = record_type

            if "data" not in nested_elem:
                nested_elem["data"] = OrderedDict()

            nested_elem["data"][parent] = {}

            param["nesting"].append(parent)
        else:
            param["type"] = record_type
            param["nesting"] = [parent]
            param["data"] = OrderedDict()
            param["data"][parent] = {}

        """
        int (*myfunc)(int a);

        params["a"] = { "type": "int", "data": b"\00" }

        struct SomeStruct {
            uint32_t member_a;
            uint32_t member_b;
            uint64_t member_c;
        };

        struct MyStruct {
            int (*myfunc)(SomeStruct_t *a);
        }

        params["a"] = {
            "type": "struct SomeStruct",
            "data": OrderedDict{
                "member_a": {
                    "type": "uint32_t",
                    "data": b"\x00"
                },
                "member_b" : {
                    "type": "struct Foo",
                    "data": OrderedDict{
                        "member_a": {
                            "type": "uint32_t",
                            "data": b"\x00"
                        }
                    }
                }
            }
        }

        params["a"]["data"]["member_a"]["data"]
        """

    elif msg_type == "close_record_ctx":
        param_name = payload["param_name"]
        param_type = payload["record_type"]
        is_onenter = payload["on_enter"]

        hook = "onEnter" if is_onenter else "onLeave"
        params = dump[hook]["params"]
        param = params[param_name]

        param["nesting"].pop()

    elif msg_type == "open_array_ctx":
        param_name = payload["param_name"]
        parent = payload["parent"]
        array_type = payload["array_type"]
        is_onenter = payload["on_enter"]

        hook = "onEnter" if is_onenter else "onLeave"
        param = dump[hook]["params"][param_name]

        if "nesting" in param:
            # this is a nested array
            nested_elem = param
            for nested_elem_key in param["nesting"]:
                nested_elem = nested_elem["data"][nested_elem_key]

            nested_elem["type"] = array_type
            if "data" not in nested_elem:
                nested_elem["data"] = OrderedDict()

            nested_elem["data"][parent] = {}
            param["nesting"].append(parent)
        else:
            param["type"] = array_type
            param["nesting"] = [parent]
            param["data"] = OrderedDict()
            param["data"][parent] = {}

    elif msg_type == "close_array_ctx":
        param_name = payload["param_name"]
        param_type = payload["array_type"]
        is_onenter = payload["on_enter"]

        hook = "onEnter" if is_onenter else "onLeave"
        params = dump[hook]["params"]
        param = params[param_name]

        param["nesting"].pop()
    elif msg_type == "dump":
        func_name = payload["func_name"]
        param_name = payload["param_name"]
        leaf_name = payload["leaf_name"]
        leaf_type = payload["param_type"]
        is_onenter = payload["on_enter"]

        # if we do not have data for this parameter, we do not save it
        if not data:
            return

        hook = "onEnter" if is_onenter else "onLeave"
        params = dump[hook]["params"]
        param = params[param_name]

        # pprint(DATA)
        # import ipdb

        # ipdb.set_trace()

        if "nesting" in param and len(param["nesting"]) > 0:
            for nested_elem_key in params[param_name]["nesting"]:
                param = param["data"][nested_elem_key]
            if "data" not in param:
                param["data"] = OrderedDict()

            if leaf_name not in param["data"]:
                param["data"][leaf_name] = {}

            param = param["data"][leaf_name]

        if "type" not in param:
            param["type"] = leaf_type

        if "data" not in param:
            # recording a scalar
            param["data"] = data
        elif not isinstance(param["data"], list):
            # convert to `list` representing an array
            param["data"] = [param["data"]]
            param["data"].append(data)
        else:
            # appending to an array
            param["data"].append(data)

        # log.info(hexdump.hexdump(data))
    else:
        log.error("What's this?")
        import ipdb

        ipdb.set_trace()


def on_message(msg, data):

    if msg["type"] == "error":
        raise RecordingException(f"Remote encountered an error:\n{msg['stack']}")
    elif msg["type"] == "send" and "payload" in msg:
        handle_send_message(msg, data)
    else:
        raise RecordingException(f"Unexpected message type {msg['type']}")


def get_high_lvl_id() -> int:
    global HIGHLVL_ID
    return HIGHLVL_ID


def store_recording(data, seqid, procdir, high_lvl_id):
    global HIGHLVL_ID

    func_dir = os.path.join(
        procdir, str(seqid), str(high_lvl_id), f"{data['func']}_{data['dump_id']}"
    )
    if not os.path.isdir(func_dir):
        mkdir_p(func_dir)

    # mkdir onenter
    onenter_dir = os.path.join(func_dir, "onenter")
    os.mkdir(onenter_dir)
    for arg in data["onEnter"]["params"].keys():
        file_path = os.path.join(onenter_dir, arg)
        if data["onEnter"]["params"][arg]:
            with open(file_path, "wb") as f:
                pickle.dump(data["onEnter"]["params"][arg], f)

    # mkdir onleave
    onleave_dir = os.path.join(func_dir, "onleave")
    os.mkdir(onleave_dir)
    for arg in data["onLeave"]["params"].keys():
        file_path = os.path.join(onleave_dir, arg)
        if data["onLeave"]["params"][arg]:
            with open(file_path, "wb") as f:
                pickle.dump(data["onLeave"]["params"][arg], f)

    if not data["func"].endswith("hidl_cb"):
        # we received data from a non-callback high-level function and therefore
        # move to the next storage directory for future data
        HIGHLVL_ID += 1



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
        store_recording(elem, sequence_id, process_dir, HIGHLVL_ID)


def main(dbii_js, ca, out_dir):

    dumpq_worker = Thread(target=handle_dump_q, args=(Q, ca, out_dir))
    dumpq_worker.setDaemon(True)  # exit when main thread terminates
    dumpq_worker.start()

    ############################################################################
    # frida setup
    ############################################################################

    device = frida.get_usb_device()

    # establish session with target ca
    session = device.attach(ca)

    # read dbii script for target ca
    with open(dbii_js) as f:
        script = session.create_script(f.read())

    # register `message` callback
    script.on("message", on_message)
    script.load()

    ############################################################################
    # recording
    ############################################################################

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