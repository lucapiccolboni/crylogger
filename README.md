## Introduction

*CRYLOGGER* detects cryptographic (crypto) misuses in Android apps. A crypto misuse is an invocation to a crypto API that does not respect common security guidelines, such as those suggested by cryptographers or organizations like [NIST](https://www.nist.gov/) and [IETF](https://www.ietf.org/). For instance, *CRYLOGGER* can tell you if your Android app uses AES in ECB mode to encrypt multiple data blocks, which is bad in cryptography.

*CRYLOGGER* detects crypto misuses for you automatically, without requiring to analyze a single line of your code. First, *CRYLOGGER* runs your Android app on the official Android [Emulator](https://developer.android.com/studio/run/emulator), whose Java libraries have been instrumented to log the parameters passed to the relevant crypto APIs. Then, it analyzes the log file offline and reports all the crypto misuses.  Differently from other approaches, it does *not* employ static analysis. *CRYLOGGER* runs your app by using [Monkey](https://developer.android.com/studio/test/monkey) or the user-interface events you send to the emulator.

If you want to know more about *CRYLOGGER*, please contact me at
piccolboni@cs.columbia.edu or read our Oakland paper:

```
Luca Piccolboni, Giuseppe Di Guglielmo, Luca P. Carloni and Simha Sethumadhavan, "CRYLOGGER:
Detecting Crypto Misuses Dynamically", in IEEE Symposium on Security and Privacy (SP), 2021.
```

***

## Requirements

There are not a lot of requirements that are specific to *CRYLOGGER*. If you satisfy the requirements of the [AOSP](https://source.android.com/setup/build/requirements) and you install all the Python packages required for `scripts/run.py` and `scripts/check.py` you are good to go! *CRYLOGGER* has been tested on *Android-9.0.0_r36* (this is the default version of the emulator that is installed as explained below). It should be easy to adapt it to other Android builds. For the host machine, we used a machine with a clean installation of *Ubuntu 18.04.1*.

Make sure you install the [Android SDK](https://developer.android.com/studio) if you want to compile the test app included in this repository (directory `test-app`) and set the environment variable `ANDROID_SDK_ROOT` to point to it.

## Emulator Setup

Once you satisfy the requirements of the AOSP, it is sufficient to run the following command to setup the emulator and *CRYLOGGER*:

```bash
cd scripts/setup
./setup_emu.py
```

This scripts downloads the AOSP in a new directory `android-emu` from the official Google repositories, installs *CRYLOGGER* by copying the files from the directory `scripts/deltas`, and builds it. Please refer to the scripts in the directory `scripts/setup` for more information. By default, it uses all the available cores to compile the AOSP.

In addition, if you want to install apps from the Google Play Store, you need to install the [OpenGApps](https://github.com/opengapps/opengapps). You can do so by running the following commands:

```bash
cd scripts/setup
./setup_opengapps.sh
```

The OpenGApps (*x86-9.0-super-20200103*) are downloaded in `script/opengapps` so they can be installed on the emulator.

***

## Verify your App

You are now ready to run your app on the Android emulator and collect the log that contains information about the crypto APIs that are invoked. We call this log *"cryptolog"*. Here, we verify a simple Android app that you can find in the directory `app-test`. If you have your own APK to test, you can skip the compilation of `app-test`, otherwise:

```bash
cd app-test
./gradlew build
```

If the compilation is successfull, you should find a file named `com.example.aes_0.apk` in the folder `test-app` that points to the APK of the test app. If you use your APK, make sure you use the following naming convention: `<package_name>_<version>.apk`, where `<package_name>` is the package name of the Android app and `<version>` is its version number. Copy the APK in the directory `scripts/data/apks`:

```bash
cp app-test/com.example.aes_0.apk scripts/data/apks/
```

You need to start the emulator by passing the option `-writable-system` (this option is only used to install the OpenGApps):

```bash
# Setup the env variables
cd android-emu
source build/envsetup.sh
lunch sdk_phone_x86-userdebug
# Now start the emulator
emulator -writable-system
```

### Collect the logs

The emulator should be now running. Wait for the completion of the boot process, and then run the following script to execute your app:

```bash
cd scripts
python run.py --work_dir data --session emulator-<number>
```

where `<number>` is the emulator session number (you can find it in the title bar of the emulator window). By default the script `run.py` (1) installs the OpenGApps, if they have not been installed in a previous run, (2) configures the  emulator, so that your app can be tested with Monkey, (3) installs your app on the emulator, (4) runs your app with Monkey by using a fixed number of user-interface events (default *100*), (5) collects the cryptolog, which contains information about the use of the crypto APIs, and (6) uninstalls the app. You can easily modify the script `run.py` if you want to use your own user-generated events.

### Analyze the logs

After 'run.py' completes, you should find the log in the directory `scripts/data/crypto_logs`. Now you can analyze them by running the following command:

```bash
cd scripts
python check.py --work_dir data/crypto_logs --rule_ID <number>
```

where `<number>` is the number of the crypto rule you want to check. *CRYLOGGER* support *26* rules that are explained in the paper as well as in the script `check.py`. These rules are suggested by cryptographers or organizations like [NIST](https://www.nist.gov/) and [IETF](https://www.ietf.org/). Try for example to check rule *R-03* by using the following command:

```bash
cd scripts
python check.py --work_dir data/crypto_logs --rule_ID 03
```

You should obtain a file with extension `.rules` in the directory `scripts/data/crypto_logs` that tells you if rule *R-03* is violated. For the app included in this repository the rule should be violated because the app performs encryptions and decryptions by using the insecure ECB mode. Note that some rules require two executions of your app, thus you need to run the script `run.py` twice. The second run should look like this:

```bash
cd scripts
python run.py --work_dir data --session emulator-<number> --suffix 2
```

This command runs again your app on the emulator and appends `'2'` to the cryptolog files (extension `.cryptolog2` instead of simply `.cryptolog`). You can check rules that require two executions, for example rule *R-05* with the following command:

```bash
cd scripts
python check.py --work_dir data/crypto_logs --rule_ID 05
```

If you want to check all the rules supported by *CRYLOGGER*, omit the flag `--rule_ID`.
