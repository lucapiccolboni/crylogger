#!/bin/bash

# Author: Luca Piccolboni (piccolboni@cs.columbia.edu)
# This script downloads the OpenGApps and installs them

OPENGAPPS_NAME="open_gapps-x86-9.0-super-20200103.zip"
OPENGAPPS_LINK="https://sourceforge.net/projects/opengapps/files/x86/20200103/${OPENGAPPS_NAME}"

# 1. Download OpenGApps
wget ${OPENGAPPS_LINK} &>/dev/null
echo "Info: OpenGApps have been downloaded"

# 2. Unzip OpenGapps
rm -rf ../opengapps
mkdir ../opengapps
cd ../opengapps
mv ../setup/${OPENGAPPS_NAME} ./
unzip ${OPENGAPPS_NAME} &>/dev/null
rm Core/setup*
lzip -d Core/*.lz
for f in $(ls Core/*.tar); do
     tar -x --strip-components 2 -f $f
done
echo "Info: OpenGApps have been unzipped"
cd ../setup
