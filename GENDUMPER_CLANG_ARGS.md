# FINDING CLANG ARGUMENTS FOR GENDUMP
In order to use gendumper correctly we need to identify the exact clang arguments, intermediate builds and correct dependencies. This process is not always trivial, we hope that with this document the process might become a bit easier. 

# Building Keymaster
Let us start by showing working commands for Keymaster, then we show how to obtain them. In order to generate the js file for the struct `IKeymasterDevice` the following command is issued : 
```bash
python3.8 -m generator.gendumper 'KeymasterDevice' /in/targets/hikey620/aosp/out_dir/KeymasterDevice.hpp -I/in/targets/hikey620/aosp/out_dir/ -I/in/targets/hikey620/aosp/system/libhidl/base/include/  -I/in/targets/hikey620/aosp/system/core/libcutils/include/  -I/in/targets/hikey620/aosp/system/core/libutils/include/  -I/in/targets/hikey620/aosp/system/libfmq/base/ -std=c++17  > newDump.js
```
As you can see there are many libraries that need to be included and we have to explicitly tell clang that we want to use C++17, if we don't we will receive errors that would lead us nowhere.
For Keymaster Optee the command is as follows:
```bash
python3.8 -m generator.gendumper "OpteeKeymaster3Device" /in/targets/hikey620/aosp/external/apps/keymaster/include/optee_keymaster/optee_keymaster3_device.h -I/in/targets/hikey620/aosp/out_dir/ -I/in/targets/hikey620/aosp/system/libhidl/base/include/  -I/in/targets/hikey620/aosp/system/core/libcutils/include/  -I/in/targets/hikey620/aosp/system/core/libutils/include/  -I/in/targets/hikey620/aosp/system/libfmq/base/ -I/in/targets/hikey620/aosp/external/apps/keymaster/include/ -I/in/targets/hikey620/aosp/system/keymaster/include  -I/in/targets/hikey620/aosp/hardware/libhardware/include/  -xc++  -std=c++17 > gendump_opteeKeymaster.js
```
As you can see this one is a bit trickier, note the argument `xc++`, this is required in order to instruct clang to treat `.h` files as **C++** files.

# How to find the commands
## SETUP 
In order to find the commands for yourself you have to download the android aosp project. We here point you towards android documentation to get the source code and the environment setup: [Android Source ](https://source.android.com/docs/setup/download), [Repo client](https://source.android.com/docs/setup/download/downloading) 

After following Google's guide and obtaining the `aosp` directory with the source code, `cd` into it. Let's launch:
`. build/envsetup.sh` to source the android environment configuration.
After this, we need to make the android dependencies needed. Firstly, let's set the target platform with `lunch`. In our case we did `lunch hikey-userdebug` Then let's make the dependencies, for simplicity we just build everything, note that it will take some time. From the top of the tree launch : `m`. 
Once everything is built, we can go to the modules we're interested in.
## Getting that Keymaster
Let's go inside key master's directory `cd hardware/interfaces/keymaster/3.0`. From here we want to launch `mm showcommands > commands`. After that we will have a file with all the instructions executed by the android build system. If we analyze the file we will find a line like the following : 
```bash
prebuilts/clang/host/linux-x86/clang-4691093/bin/clang++ -c -Ihardware/interfaces/keymaster/3.0 -mthumb -Os -fomit-frame-pointer -DANDROID -fmessage-length=0 -W -Wall -Wno-unused -Winit-self -Wpointer-arith -no-canonical-prefixes -DNDEBUG -UDEBUG -fno-exceptions -Wno-multichar -O2 -g -fno-strict-aliasing -fdebug-prefix-map=/proc/self/cwd= -D__compiler_offsetof=__builtin_offsetof -Werror=int-conversion -Wno-reserved-id-macro -Wno-format-pedantic -Wno-unused-command-line-argument -fcolor-diagnostics -Wno-expansion-to-defined -Wno-zero-as-null-pointer-constant -fdebug-prefix-map=$PWD/= -ffunction-sections -fdata-sections -fno-short-enums -funwind-tables -fstack-protector-strong -Wa,--noexecstack -D_FORTIFY_SOURCE=2 -Wstrict-aliasing=2 -Werror=return-type -Werror=non-virtual-dtor -Werror=address -Werror=sequence-point -Werror=date-time -Werror=format-security -nostdlibinc -msoft-float -march=armv7-a -mfloat-abi=softfp -mfpu=neon  -Isystem/libhidl/adapter/include -Isystem/libhidl/base/include -Isystem/core/libcutils/include -Isystem/core/libutils/include -Isystem/core/libbacktrace/include -Isystem/core/liblog/include -Isystem/core/libsystem/include -Isystem/libhidl/transport/include -Iout/soong/.intermediates/system/libhidl/transport/manager/1.0/android.hidl.manager@1.0_genc++_headers/gen -Iout/soong/.intermediates/system/libhidl/transport/manager/1.1/android.hidl.manager@1.1_genc++_headers/gen -Iout/soong/.intermediates/system/libhidl/transport/base/1.0/android.hidl.base@1.0_genc++_headers/gen -Iout/soong/.intermediates/system/libhidl/transport/base/1.0/android.hidl.base@1.0-adapter-helper_genc++_headers/gen -Isystem/libhwbinder/include -Isystem/core/base/include -Iout/soong/.intermediates/hardware/interfaces/keymaster/3.0/android.hardware.keymaster@3.0_genc++_headers/gen -Iexternal/libcxx/include -Iexternal/libcxxabi/include -Iout/soong/.intermediates/hardware/interfaces/keymaster/3.0/android.hardware.keymaster@3.0-adapter-helper_genc++/gen -Iout/soong/.intermediates/hardware/interfaces/keymaster/3.0/android.hardware.keymaster@3.0-adapter-helper_genc++_headers/gen -Isystem/core/include -Isystem/media/audio/include -Ihardware/libhardware/include -Ihardware/libhardware_legacy/include -Ihardware/ril/include -Ilibnativehelper/include -Iframeworks/native/include -Iframeworks/native/opengl/include -Iframeworks/av/include -isystem bionic/libc/include -isystem bionic/libc/kernel/uapi -isystem bionic/libc/kernel/uapi/asm-arm -isystem bionic/libc/kernel/android/scsi -isystem bionic/libc/kernel/android/uapi -Ilibnativehelper/include_jni -Wall -Werror -Wextra-semi -D__ANDROID_DEBUGGABLE__ -target arm-linux-androideabi -Bprebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9/arm-linux-androideabi/bin -DANDROID_STRICT -fPIC -D_USING_LIBCXX -std=gnu++14 -Wsign-promo -Wno-inconsistent-missing-override -Wno-null-dereference -D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS -Wno-thread-safety-negative -Wno-gnu-include-next -fvisibility-inlines-hidden -fno-rtti  -Werror=int-to-pointer-cast -Werror=pointer-to-int-cast -Werror=address-of-temporary -Werror=return-type -Wno-tautological-constant-compare -Wno-null-pointer-arithmetic -Wno-enum-compare -Wno-enum-compare-switch -MD -MF 'out/soong/.intermediates/hardware/interfaces/keymaster/3.0/android.hardware.keymaster@3.0-adapter-helper/android_arm_armv7-a-neon_core_static/obj/.intermediates/hardware/interfaces/keymaster/3.0/android.hardware.keymaster@3.0-adapter-helper_genc++/gen/android/hardware/keymaster/3.0/AKeymasterDevice.o'.d -o 'out/soong/.intermediates/hardware/interfaces/keymaster/3.0/android.hardware.keymaster@3.0-adapter-helper/android_arm_armv7-a-neon_core_static/obj/.intermediates/hardware/interfaces/keymaster/3.0/android.hardware.keymaster@3.0-adapter-helper_genc++/gen/android/hardware/keymaster/3.0/AKeymasterDevice.o' 'out/soong/.intermediates/hardware/interfaces/keymaster/3.0/android.hardware.keymaster@3.0-adapter-helper_genc++/gen/android/hardware/keymaster/3.0/AKeymasterDevice.cpp'
```
Let's start then from a basic command for our gendumper and work our way up 
`python3.8 -m generator.gendumper 'KeymasterDevice' /in/targets/hikey620/aosp/out_dir/KeymasterDevice.hpp -I/in/targets/hikey620/aosp/out_dir/`, we see that the output of gendumper tells us that we have missing dependencies such as libHidl, so we find libhidl in our `commands` file, look at the directory and simply add it to our gendumper command. Hopefully with this approach you can generate commands for any android module!

## Troubleshooting
### algorithm not found
Make sure that you are telling clang that you want to use `h` files as `hpp`.
### Unit not found in TU or Non helpful crash log
Try running `clang -cc1 -ast-dump $target $args` and check the output. If clang gives some errors you have a clue of what's not working 
### Static assertion failed for flex 
Try rebuilding the flex module:
```bash
cd prebuilts/misc/linux-x86/flex/
tar zxf flex-2.5.39.tar.gz
cd flex-2.5.39/
./configure
make
```
