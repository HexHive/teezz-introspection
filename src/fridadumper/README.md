
## Setup

```
$ virtualenv -p python3 .venv
$ . .venv/bin/activate
$ pip install -r requirements.txt
```

Frida-based recorder logic for ioctl calls to the TEE driver.

Start the `frida-server` on the device.

## TrustedCore

### Keymaster

### Gatekeeper TA

### Fingerprint TA

Start the host component to record `ioctl` messages passed to the fingerprint TA:

```
python ./fridadump.py tc/tc_ioctl_dump.js vendor.huawei.hardware.biometrics.fingerprint@2.1-service
```

Events causing communication with the fingerprint TA:

* Navigate to `Settings` and register/enroll a new fingerprint.
* Lock the screen of the device by pressing the power button and unlock the phone via fingerprint auth.
* Delete the previously enrolled fingerprint.

For all of these actions, the host component should indicate that it is seeing `TC_NS_CLIENT_IOCTL_SEND_CMD_REQ` `ioctl`s.
Hit 's' for 'save' in the host component terminal and 'q' for 'quit' to terminate recording.
Sometimes quitting does not work. In this case, `Ctrl+z` to background the process and `kill %1` to terminate the host component manually.

The recorded `ioctl` messages are stored in `./data`.
You can 'save' the (so far) recorded messages in individual directories.
This allows to distinguish a group of messages that belong to a UI action.
In the above example, you could hit 's' after enrolling, after unlocking, and after deleting the fingerprint to generate three different direcotries containing the messages connected with an individual action.

## OPTEE

The `ioctl` recording for OPTEE in an AOSP setup works very similar to the setup on Android devices (see TrustedCore above).
It differs for an OPTEE setup with arm64 Linux normal world, which is the default OPTEE deployment using qemuv8.

Most of the currently available OPTEE CAs do not run as daemons.
They are started and run to finish in a single go.
Consequently, we cannot use the `frida-server` setup described above to attach to a daemon.
Instead, we are using `frida-gadget` and `LD_PRELOAD` to make the executable wait until we have installed our recording hooks and then let it run.

All that is needed for this is to inject `frida-gadget` into the process using `LD_PRELOAD` and a config file residing in the same directory as the `libgadget.so` (you can name `frida-gadet` however you want) with a `.config` suffix.

An example `*.config` looks like this:
```
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27042,
    "on_load": "wait"
  }
}
```

## Troubleshooting

Q: The newest `frida-server` and/or `frida-gadget` does not work on Linux/OPTEE.
A: Use version `14.*`.
