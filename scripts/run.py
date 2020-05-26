#!/usr/bin/python3

# Author: Luca Piccolboni (piccolboni@cs.columbia.edu)
# This script runs automated tests on a set of Android applications.

import os
import sys
import time
import argparse
import subprocess
import shutil

###############################################################################
# Common functions
###############################################################################


def run_cmd(cmd):

    split = cmd.split(" ")

    # Debug
    logfile = open("crash.log", "a")
    logfile.write(cmd + "\n")
    logfile.close()

    try:

        # Return the full standard output
        return subprocess.check_output(split, stderr=subprocess.STDOUT).decode("utf-8")

    except subprocess.CalledProcessError as e:

        # Debug
        output = e.output.decode("utf-8")
        logfile = open("crash.log", "a")
        logfile.write("---------------")
        logfile.write(output)
        logfile.close()

        # Just return an error string
        return str("Error")


def run_adb(args, cmd):

    output = run_cmd("adb -s " + args.session + " " + cmd)
    return output


def run_monkey(args, cmd):

    output = run_adb(args, "shell monkey " + cmd)
    return output


def run_am(args, cmd):

    output = run_adb(args, "shell am " + cmd)
    return output

###############################################################################
# 0. Print info
###############################################################################


def print_info_apk(args):

    # Expect the following format: package_vers.apk

    args.apk_path = os.path.join(args.apk_dir, args.file_name)
    args.app_name = args.file_name[:args.file_name.rfind("_")]
    args.app_vers = args.file_name[args.file_name.rfind("_")+1:-4]

    print("Running:")
    print("\t app        | " + args.app_name + " (" + args.app_vers + ")")

    return 0

###############################################################################
# 1. Install the apk
###############################################################################


def install_apk(args):

    # Note: -g grants all the permissions to the app
    output = run_adb(args, "install -g " + args.apk_path)
    if output == "Error":
        print("\t install    | failed")
        return 1

    print("\t install    | success")
    return 0

###############################################################################
# 2. Pin the application
###############################################################################


def pin_application(args):

    # Make sure the application is running
    output = run_monkey(args, "-p " + args.app_name +
                        " -c android.intent.category.LAUNCHER 1")
    if output == "Error":
        print("\t pinning    | failed (run)")
        return 1

    # Make sure that wifi is actually enabled
    output = run_adb(args, "shell svc wifi enable")
    if output == "Error":
        print("\t pinning    | failed (wifi)")
        return 1

    # Make sure that data is actually enabled
    output = run_adb(args, "shell svc data enable")
    if output == "Error":
        print("\t pinning    | failed (data)")
        return 1

    # Enable the immersive mode for testing
    output = run_adb(args, "shell settings put global" +
                     " policy_control immersive.full=*")
    if output == "Error":
        print("\t pinning    | failed (imm)")
        return 1

    # Remove quick settings wifi/etc and leave battery
    output = run_adb(args, "shell settings put secure sysui_qs_tiles battery")
    if output == "Error":
        print("\t pinning    | failed (quick)")
        return 1

    # Get the ID of the task of the application to pin
    taskid = run_am(args, "stack list | grep " + args.app_name +
                    " | cut -d\":\" -f1 | cut -d \"=\" -f2")
    if taskid == "Error":
        print("\t pinning    | failed (stack)")

    # Pin the application so Monkey can focus on that
    output = run_am(args, "task lock " + taskid)
    if output == "Error":
        print("\t pinning    | failed (pin)")
        return 1

    print("\t pinning    | success")
    return 0

###############################################################################
# 3. Run automated testing
###############################################################################


monkey_args = "--ignore-crashes  " + \
              "--ignore-timeouts " + \
              "--ignore-native-crashes " + \
              "--ignore-security-exceptions " + \
              "--randomize-throttle " + \
              "--pct-syskeys 0 " + \
              "-v -s 12345 100"


def run_monkey_test(args):

    monkeylog = args.file_name.replace("apk", "monkey")
    monkeylog = os.path.join(args.monkey_dir, monkeylog)

    start = time.time()
    output = run_monkey(args, "-p " + args.app_name + " " + monkey_args)
    end = time.time()
    if output == "Error":
        print("\t monkey     | failed")
        return 1

    # Save the monkey's log
    logfile = open(monkeylog, "w")
    logfile.write(output)
    logfile.close()

    print("\t monkey     | success (" + str(round(end - start, 2)) + "s)")
    return 0

###############################################################################
# 4. Unpin the application
###############################################################################


def unpin_application(args):

    # Unpin the application
    output = run_am(args, "task lock stop")
    if output == "Error":
        print("\t unpinning  | failed")
        return 1

    print("\t unpinning  | success")
    return 0

###############################################################################
# 5. Get crypto log
###############################################################################


def get_crypto_log(args):

    srclog = "application.cryptolog"
    dstlog = args.app_name + "_" + args.app_vers + ".cryptolog"

    if args.suffix:
        dstlog = dstlog + str(args.suffix)

    time.sleep(5)
    output = run_adb(args, "pull /data/data/" + args.app_name +
                     "/cache/" + srclog + " .")
    if output == "Error":
        print("\t cryptolog  | failed")
        return 1
    if "No such file" in output:
        print("\t cryptolog  | not found")
        return 0

    # Cache the file for later uses in `instr_dir`
    shutil.move(srclog, os.path.join(args.crypto_dir, dstlog))

    print("\t cryptolog  | success")
    return 0

###############################################################################
# 6. Uninstall apk
###############################################################################


def uninstall_apk(args):

    output = run_adb(args, "uninstall " + args.app_name)
    if output == "Error":
        print("\t uninstall  | failed")
        return 1

    print("\t uninstall  | success")
    return 0

###############################################################################
# Env setup
###############################################################################


def setup_device_env(args):

    print("Configuring:")

    # Check if the device is connected
    output = run_adb(args, "devices")
    if args.session not in output:
        print("\t emulator   | not found")
        return 1
    print("\t emulator   | found")

    # Check if we have root permissions
    output = run_adb(args, "root")
    if "already running as root" not in output and \
       "restarting adbd as root" not in output:
        print("\t adb root   | failed")
        return 1
    print("\t adb root   | success")

    # Install the Google Play Store services
    output = run_adb(args, "shell pm list packages")
    if output == "Error":
        print("\t googleplay | failed")
        return 1

    if "google" not in output:

        # Google services are not installed
        output = run_adb(args, "remount")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        output = run_adb(args, "push ./opengapps/etc /system")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        output = run_adb(args, "push ./opengapps/app /system")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        output = run_adb(args, "push ./opengapps/priv-app /system")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        output = run_adb(args, "push ./opengapps/framework /system")
        if output == "Error":
            print("\t googleplay | failed")
            return 1

        # Restart the phone to apply the changes
        output = run_adb(args, "shell stop")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        output = run_adb(args, "shell start")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        time.sleep(15)

        # Grant all the permissions to the Google Apps
        output = run_adb(args, "remount")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        output = run_adb(args, "push ./opengapps-scripts/fix_perms.sh /sdcard")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        output = run_adb(args, "shell sh /sdcard/fix_perms.sh")
        if output == "Error":
            print("\t googleplay | failed")
            return 1
        print("\t googleplay | success")

    else:

        print("\t googleplay | cached")

    return 0


def restore_device_env(args):

    print("Configuring:")

    output = run_adb(args, "shell settings put global" +
                     " policy_control null=*")
    if output == "Error":
        print("\t immersive  | failed")
        return 1
    print("\t immersive  | success")

    return 0

###############################################################################
# Argument parser
###############################################################################


def get_parser():

    parser = argparse.ArgumentParser(prog="run_test")

    parser.add_argument("--work_dir", required=True, metavar="<path>",
                        help="the working directory of this script")
    parser.add_argument("--session", required=True, metavar="<name>",
                        help="the emulator session to use for testing")
    parser.add_argument("--suffix", required=False, metavar="<string>",
                        help="add a suffix to the crypto log")

    return parser

###############################################################################
# Main
###############################################################################


def main():

    parser = get_parser()
    args = parser.parse_args()

    if setup_device_env(args):
        return 1

    # Setting up dirs used by the above functions
    args.work_dir = os.path.abspath(args.work_dir)
    args.apk_dir = os.path.join(args.work_dir, "apks")
    args.crypto_dir = os.path.join(args.work_dir, "crypto_logs")
    args.monkey_dir = os.path.join(args.work_dir, "monkey_logs")

    for file_name in os.listdir(args.apk_dir):

        if file_name.endswith("apk"):

            args.file_name = file_name

            while True:

                # 0. Print apk info
                if print_info_apk(args):
                    break

                # 1. Install the apk
                if install_apk(args):
                    break

                # 2. Pin the application
                if pin_application(args):
                    uninstall_apk(args)
                    break

                # 3. Automated testing
                if run_monkey_test(args):
                    uninstall_apk(args)
                    break

                # 4. Unpin the application
                if unpin_application(args):
                    uninstall_apk(args)
                    break

                # 5. Get crypto log
                if get_crypto_log(args):
                    uninstall_apk(args)
                    break

                # 6. Uninstall apk
                if uninstall_apk(args):
                    break

                break

    if restore_device_env(args):
        return 1


if __name__ == "__main__":
    main()
