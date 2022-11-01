## Android-Testing

## Setup

* Android platform tools (`adb`)
* Android SDK (`aapt`)
  * requires Java (`apt install openjdk-11-jdk`)
  * install `build-tools` via [`sdkmanager`](https://developer.android.com/studio/command-line/sdkmanager)
* CTS

```
$ ./cmdline-tools/bin/sdkmanager --sdk_root=./ --list
$ ./cmdline-tools/bin/sdkmanager --sdk_root=./ "build-tools;30.0.3"
$ PATH=~/Android/build-tools/30.0.3/:$PATH
$ cts-tf > run cts -m CtsKeystoreTestCases
$ cts-tf> run cts --package android.accounts --skip-preconditions
```

### CTS (Android Compatibility Test Suite):

[CTS-Home](https://source.android.com/compatibility/cts)

#### Run standart Android CTS Tests:

* Download correct CTS Version at [CTS-Downloads](https://source.android.com/compatibility/cts/downloads?hl=en)
* Run desired Testcase:
```bash
$ ./android-cts/tools/cts-tradefed
> list modules
> run cts -m <module> -s <device sn>
```

Remote Testing:

* Start `adb devices` on remote host
* Kill local adb server and activate port-forwarding:
```bash
$ adb kill-server
$ ssh -CN -L5037:127.0.0.1:5037 -R27183:127.0.0.1:27183 <remote host>
```

Android 8 API Error:
* replace in testcase config file (./android-cts/testcases/*.config):  
`<target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">`  
with  
`<target_preparer class="com.android.compatibility.common.tradefed.targetprep.ApkInstaller">`

[Source](https://stackoverflow.com/questions/61341122/android-8-1-running-cts-shows-install-failed-no-matching-abis-failed-to-extrac)
		  
#### Make own CTS Testcases:
[CTS-Development](https://source.android.com/compatibility/cts/development?hl=en)
[HowTo](https://stackoverflow.com/questions/2824015/how-to-build-android-cts-and-how-to-add-and-run-your-test-case)
