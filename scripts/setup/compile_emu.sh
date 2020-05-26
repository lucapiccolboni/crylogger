#!/bin/bash

# Author: Luca Piccolboni (piccolboni@cs.columbia.edu)
# This script compiles the Android AOSP in android-emu

cd ../../android-emu
source ./build/envsetup.sh
lunch sdk_phone_x86-userdebug
make -j $(nproc)
cd ../scripts/setup
