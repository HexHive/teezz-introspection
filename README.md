
## SETUP :wrench:

Build the docker image:
```
make build
```

Spawn a docker container:
```
docker run \
  --privileged -it --rm \
  -v `pwd`/src:/src \
  -v `pwd`/docker/.android:/root/.android \
  -v `pwd`/docker/frida-server-14.2.7-android-arm64:/root/frida-server \
  -v /dev/bus/usb:/dev/bus/usb \
  /dev/bus/usb:/dev/bus/usbteezz-recorder /bin/bash
```

Connect Android device to your computer. Make sure the adb server on the host
is not running (`adb kill-server`) and that you see the device from inside of
the Docker container:
```
root@9ef77accf8f4:~/sdk# adb devices
List of devices attached
712KPBF1235565  device
```

Deploy and run `frida-server`:
```
adb push /root/frida-server /data/local/tmp/
adb shell

# in adb shell
su # we assume the device is rooted and you can do this
cd /data/local/tmp
chmod u+x ./frida-server
./frida-server &
```

From a shell inside of the container (e.g., `docker exec -it 9ef77accf8f4 /bin/bash`) you should be able to see:
```
root@9ef77accf8f4:/src# frida-ps -U
  PID  Name
-----  -------------------------------------------------------
  942  adbd
  877  adsprpcd
  756  android.hardware.audio@2.0-service
  933  android.hardware.biometrics.fingerprint@2.1-service.fpc
  758  android.hardware.bluetooth@1.0-service-qti
  627  android.hardware.boot@1.0-service
[...]
```

## Record ioctl Interactions

While the `frida-server` is running on the device, inject the recording hooks
into your target process:
```
cd /src
python3 -m fridadumper qsee android.hardware.keymaster@3.0-service-qti /tmp/out
```

The above command is tageting the `android.hardware.keymaster@3.0-service-qti`
service on a Pixel 2XL running the `qsee` TEE. Once the hooks are installed,
trigger some logic that makes `android.hardware.keymaster@3.0-service-qti`
interact with the TEE. For instance, go to the Settings app and change the
unlock pattern. You should see some logging output of the recorder when the
interaction is triggered. Enter `s` and hit the Enter key to save the recording,
and enter `q` and hit the Enter key to terminate the recorder.

You should find the `onenter` and `onleave` recordings of the `ioctl`s in your
`out/` directory now:

```
root@9ef77accf8f4:/src# tree /tmp/out
/tmp/out
`-- android.hardware.keymaster@3.0-service-qti
    `-- 0
        `-- 0
            |-- ioctl_65536
            |   |-- onenter
            |   |   |-- qseecom_send_cmd_req
            |   |   |-- req
            |   |   `-- resp
            |   `-- onleave
            |       |-- qseecom_send_cmd_req
            |       |-- req
            |       `-- resp
            |-- ioctl_65537
            |   |-- onenter
            |   |   |-- qseecom_send_cmd_req
            |   |   |-- req
            |   |   `-- resp
            |   `-- onleave
            |       |-- qseecom_send_cmd_req
            |       |-- req
            |       `-- resp
[...]
```

## Record HAL Interactions

Spawn the docker container using one of the `docker/envs/*.env` files.
There's a `Makefile` target that just drops you into a properly `env`ed shell.

```
# Pixel 2XL (taimen) targeting the keymaster CA as an example
make run-sh ENV_FILE=./docker/envs/taimen-km.env
```

Download the required AOSP components.

```
mkdir -p /root/workdir/aosp
cd /root/workdir/aosp
/target/get_aosp.sh
```

Generate the HAL DBII recorder.

```
cd /root/workdir
/target/gen.sh
```

While the `frida-server` is running on the device, inject the recording hooks
into your target process:
```
PYTHONPATH=/src python3 -m haldump ./recorder.js $CA /tmp/out
```

The above command is tageting the `android.hardware.keymaster@3.0-service-qti`
service on a Pixel 2XL running the `qsee` TEE. Once the hooks are installed,
trigger some logic that makes `android.hardware.keymaster@3.0-service-qti`
interact with the TEE similar to above when recording from the `ioctl` interface.
Enter `s` and hit the Enter key to save the recording,
and enter `q` and hit the Enter key to terminate the recorder.

You should find the `onenter` and `onleave` recordings of the HAL in your
`out/` directory now. This is the sequence generated when unlocking the phone
using a pattern:
```
root@51948070a8ea:~/workdir# tree /tmp/out/android.hardware.keymaster\@3.0-service-qti/
/tmp/out/android.hardware.keymaster@3.0-service-qti/
`-- 0
    |-- 0
    |   `-- getKeyCharacteristics_cb_1
    |       |-- onenter
    |       |   |-- error
    |       |   `-- keyCharacteristics
    |       `-- onleave
    |-- 1
    |   `-- getKeyCharacteristics_0
    |       |-- onenter
    |       |   |-- _hidl_cb
    |       |   |-- appData
    |       |   |-- clientId
    |       |   `-- keyBlob
    |       `-- onleave
    |           |-- _hidl_cb
    |           |-- appData
    |           |-- clientId
    |           |-- keyBlob
    |           `-- ret
    |-- 2
    |   `-- getKeyCharacteristics_cb_3
    |       |-- onenter
    |       |   |-- error
    |       |   `-- keyCharacteristics
    |       `-- onleave
    |-- 3
    |   `-- getKeyCharacteristics_2
    |       |-- onenter
    |       |   |-- _hidl_cb
    |       |   |-- appData
    |       |   |-- clientId
    |       |   `-- keyBlob
    |       `-- onleave
    |           |-- _hidl_cb
    |           |-- appData
    |           |-- clientId
    |           |-- keyBlob
    |           `-- ret
    |-- 4
    |   `-- begin_cb_5
    |       |-- onenter
    |       |   |-- error
    |       |   |-- operationHandle
    |       |   `-- outParams
    |       `-- onleave
    |-- 5
    |   `-- begin_4
    |       |-- onenter
    |       |   |-- _hidl_cb
    |       |   |-- inParams
    |       |   |-- key
    |       |   `-- purpose
    |       `-- onleave
    |           |-- _hidl_cb
    |           |-- inParams
    |           |-- key
    |           |-- purpose
    |           `-- ret
    |-- 6
    |   `-- update_cb_7
    |       |-- onenter
    |       |   |-- error
    |       |   |-- inputConsumed
    |       |   |-- outParams
    |       |   `-- output
    |       `-- onleave
    |-- 7
    |   `-- update_6
    |       |-- onenter
    |       |   |-- _hidl_cb
    |       |   |-- inParams
    |       |   |-- input
    |       |   `-- operationHandle
    |       `-- onleave
    |           |-- _hidl_cb
    |           |-- inParams
    |           |-- input
    |           |-- operationHandle
    |           `-- ret
    |-- 8
    |   `-- finish_cb_9
    |       |-- onenter
    |       |   |-- error
    |       |   |-- outParams
    |       |   `-- output
    |       `-- onleave
    `-- 9
        `-- finish_8
            |-- onenter
            |   |-- _hidl_cb
            |   |-- inParams
            |   |-- input
            |   |-- operationHandle
            |   `-- signature
            `-- onleave
                |-- _hidl_cb
                |-- inParams
                |-- input
                |-- operationHandle
                |-- ret
                `-- signature
```
