#!/usr/bin/python3

# Author: Luca Piccolboni (piccolboni@cs.columbia.edu)
# This script downloads the Android AOSP and installs CRYLOGGER

import os
import sys
import shutil
import tarfile
import subprocess
import distutils.dir_util

ANDROID_OS = "android-9.0.0_r36"
ANDROID_REPO = "https://android.googlesource.com/platform/manifest"

###############################################################################
# Common functions
###############################################################################


def run_cmd(cmd):

    split = cmd.split(" ")

    # Debug
    # print(cmd)

    try:
        # Return the full standard output
        return subprocess.check_output(split, stderr=subprocess.STDOUT).decode("utf-8")

    except subprocess.CalledProcessError as e:

        # Debug
        # print(str(e.output))

        # Just return an error string
        return str("Error")


def download():

    os.chdir("../../android-emu")

    output = run_cmd("repo init -u " + ANDROID_REPO +
                     " -b " + ANDROID_OS + " --depth=1")
    if output == "Error":
        print("Error: download failed")
        sys.exit(1)

    output = run_cmd("repo sync")
    if output == "Error":
        print("Error: download failed")
        sys.exit(1)

    os.chdir("../scripts/setup")


def apply_delta():

    os.chdir("../deltas")

    distutils.dir_util.copy_tree("libcore", "../../android-emu/libcore")
    distutils.dir_util.copy_tree("frameworks", "../../android-emu/frameworks")

    os.chdir("../setup")


def make_java():

    out = run_cmd("./compile_emu.sh")
    if out == "Error":
        print("Error: compilation failed")
        os.chdir("../scripts")
        sys.exit(1)

###############################################################################
# Main
###############################################################################


def main():

    if os.path.exists("../../android-emu"):
        shutil.rmtree("../../android-emu")

    os.mkdir("../../android-emu")

    # 1. Download java source code
    download()
    print("Info: Android has been downloaded")

    # 2. Apply our delta patches
    apply_delta()
    print("Info: CRYLOGGER has been installed")

    # 3. Compile Android sources
    make_java()
    print("Info: Android has been installed")


if __name__ == "__main__":
    main()
