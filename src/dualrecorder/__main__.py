import sys
import os
import string
import frida
import time
import random
import hexdump
import pickle
import errno
from queue import Queue
from threading import Thread
import logging


# globals we use in this script
DIR = os.path.dirname(os.path.realpath(__file__))
DATADIR = os.path.join(DIR, "data")
ALNUM = list(string.ascii_letters + string.digits)
DATA_KEYS = {}
DATA = {}
HIGHLVL_ID = 0
Q = Queue()  # msg q from frida `on_message` handler to data-storing thread


logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class DumperCmd:
    SAVE = 's'
    QUIT = 'q'


# thx https://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def store_low_lvl_recording(dump, seqid, procdir):
    transaction_dir = os.path.join(procdir, str(seqid), str(HIGHLVL_ID))
    if not os.path.isdir(transaction_dir):
        mkdir_p(transaction_dir)

    log.info("#######")

    id_dir = os.path.join(transaction_dir, f"ioctl_{dump['dump_id']}")
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


def store_high_lvl_recording(data, seqid, procdir):
    global HIGHLVL_ID
    func_dir = os.path.join(procdir, str(seqid), str(HIGHLVL_ID), f"{data['func']}_{data['dump_id']}")
    if not os.path.isdir(func_dir):
        mkdir_p(func_dir)

    # mkdir onenter
    onenter_dir = os.path.join(func_dir, "onenter")
    os.mkdir(onenter_dir)
    for arg in data['onEnter']['params'].keys():
        file_path = os.path.join(onenter_dir, arg)
        if data['onEnter']['params'][arg]:
            with open(file_path, "wb") as f:
                pickle.dump(data['onEnter']['params'][arg], f)

    # mkdir onleave
    onleave_dir = os.path.join(func_dir, "onleave")
    os.mkdir(onleave_dir)
    for arg in data['onLeave']['params'].keys():
        file_path = os.path.join(onleave_dir, arg)
        if data['onLeave']['params'][arg]:
            with open(file_path, "wb") as f:
                pickle.dump(data['onLeave']['params'][arg], f)

    if not data['func'].endswith("hidl_cb"):
        # we received data from a non-callback high-level function and therefore
        # move to the next storage directory for future data
        HIGHLVL_ID += 1


def handle_dump_q(q, process):

    process_dir = os.path.join(DATADIR, process)
    if not os.path.isdir(process_dir):
        os.mkdir(process_dir)

    log.info("Dumps can be found in {}".format(process_dir))
    sequence_id = 0

    while True:
        qentry = q.get()
        if qentry == DumperCmd.SAVE:
            sequence_id += 1
            continue
        elif qentry == DumperCmd.QUIT:
            return
        elif isinstance(qentry, dict):
            if qentry['lvl'] == 'high':
                store_high_lvl_recording(qentry["data"], sequence_id, process_dir)
            elif qentry['lvl'] == 'low':
                store_low_lvl_recording(qentry["data"], sequence_id, process_dir)
            else:
                assert False, "We should always have a lvl assigned here"


def init_low_lvl_recording(msg, key):
    log.info(msg['payload']['dump_id'])
    log.info(msg['payload']['name'])
    DATA[key]['struct'] = msg['payload']['name']
    DATA[key]['cmd'] = msg['payload']['cmd']
    DATA[key]['onEnter'] = {}
    DATA[key]['onLeave'] = {}
    timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')
    DATA[key]['time'] = timestamp


def update_low_lvl_recording(msg, key, data):
    log.info(msg['payload']['dump_id'])
    if msg['payload']['on_enter']:
        DATA[key]['onEnter'][msg['payload']['type']] = data
    else:
        DATA[key]['onLeave'][msg['payload']['type']] = data


def finalize_low_lvl_recording(key):
    # dumping done. send it through the Q and delete it from our dict
    Q.put({"lvl": "low", "data": DATA[key]})
    del DATA[key]


def init_high_lvl_recording(msg, key):
    log.info(msg['payload']['dump_id'])
    DATA[key]['func'] = msg['payload']['func']
    DATA[key]['onEnter'] = {'params': {}}
    DATA[key]['onLeave'] = {'params': {}}
    timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')
    DATA[key]['time'] = timestamp


def update_high_lvl_recording(msg, key, data):

    if not data:
        return

    #log.info(hexdump.hexdump(data))
    arg_data = (msg['payload']['param_type'],  data)

    if msg['payload']['on_enter']:
        if msg['payload']['param'] not in DATA[key]['onEnter']['params']:
            DATA[key]['onEnter']['params'][msg['payload']['param']] = []
        DATA[key]['onEnter']['params'][msg['payload']['param']].append(arg_data)
    else:
        if msg['payload']['param'] not in DATA[key]['onLeave']['params']:
            DATA[key]['onLeave']['params'][msg['payload']['param']] = []
        DATA[key]['onLeave']['params'][msg['payload']['param']].append(arg_data)


def finalize_high_lvl_recording(key):
    # dumping done. send it through the Q and delete it from our dict
    Q.put({"lvl": "high", "data": DATA[key]})
    del DATA[key]


def on_message(msg, data):

    if msg['type'] == 'error':
        # print the error mesage if we receive 'error' as type
        print(msg['stack'])
    elif msg['type'] == 'send' and 'payload' in msg:
        print(msg)
        dump_id = msg['payload']['dump_id']
        if dump_id not in DATA_KEYS:
            random.shuffle(ALNUM)
            DATA_KEYS[dump_id] = "{}_{}".format("".join(ALNUM[:10]), dump_id)
        data_key = DATA_KEYS[dump_id]

        if data_key not in DATA:
            DATA[data_key] = {'dump_id': dump_id}

        if msg['payload']['type'] == "init_dump":
            # this is the start of a high-level dump
            init_high_lvl_recording(msg, data_key)
        elif msg['payload']['type'] == "dump":
            # data belonging to high-level dump with same `dump_id`
            update_high_lvl_recording(msg, data_key, data)
        elif msg['payload']['type'] == "fini_dump":
            # finish high-level dump
            finalize_high_lvl_recording(data_key)
            del DATA_KEYS[dump_id]
        elif msg['payload']['type'] == "struct":
            # this is the start of a low-level dump
            init_low_lvl_recording(msg, data_key)
        elif msg['payload']['type'] == 'done':
            # finish a low-level dump
            finalize_low_lvl_recording(data_key)
            del DATA_KEYS[dump_id]
        else:
            # data belonging to low-level dump with same `dump_id`
            update_low_lvl_recording(msg, data_key, data)
    else:
        # what is this?
        import ipdb; ipdb.set_trace()


def main(js, process):

    # set up thread to persist the dumps to disk
    dumpq_worker = Thread(target=handle_dump_q, args=(Q, process))
    dumpq_worker.setDaemon(True)  # exit when main thread terminates
    dumpq_worker.start()

    # set up the frida connection to the device and target process
    device = frida.get_usb_device()
    # device = frida.get_device_manager().add_remote_device("localhost:4242")
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
            # tell the worker to terminate and wait for it
            Q.put(DumperCmd.QUIT)
            dumpq_worker.join()
            log.info("We're done here!")
            # detach the target process
            session.detach()
            break
        else:
            log.info("Unknown cmd {}.".format(cmd))


def usage():
    print("{} <script.js> <daemon>\n\n"
          "Examples:\n"
          "\t{} qsee_ioctl_dump.js android.hardware.keymaster@3.0-service-qti\n"
          "\t{} tc_ioctl_dump.js android.hardware.keymaster@3.0-service\n"
          .format(sys.argv[0], sys.argv[0], sys.argv[0]))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit()
    main(sys.argv[1], sys.argv[2])
