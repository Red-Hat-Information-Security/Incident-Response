#!/bin/bash

#
# Download And Run UAC
#

# Some up front work

UACTMP='/tmp/uac-main'

# What's my OS?

PLATFORM='unknown'
UNAMESTR=$(uname)
if [[ $UNAMESTR == 'Linux' ]]; then
   PLATFORM='linux'
elif [[ $UNAMESTR == 'Darwin' ]]; then
   PLATFORM='macos'
fi

# What's my name?

HOSTNAME=$(hostname)

# Download UAC; do everything out of /tmp. Don't dirty up /

cd /tmp
echo "Downloading UAC..."

# Depending on the type of OS, we download UAC using the native tool.

if   [[ $OSTYPE == "linux-gnu"* ]]; then
        wget -q -O uac-main.tar.gz https://github.com/tclahr/uac/archive/refs/heads/master.tar.gz
elif [[ $OSTYPE == "darwin"* ]]; then
        curl -o uac-main.tar.gz -sLJO https://github.com/tclahr/uac/archive/refs/heads/master.tar.gz
fi

sleep 5

# Unroll UAC

echo "Extracting UAC..."
tar -zxf uac-main.tar.gz

# Some clean up

echo "Cleaning up unnecessary files..."
rm -f  uac-main.tar.gz
sleep 5

# Starting UAC collection

START_TIME=$(date +%Y%m%d%H%M%S)

echo "Starting UAC collection run at $(date +%Y-%m-%d-%H:%M:%S)"

# Run UAC in background and log the results

 bash -c "cd $UACTMP ; ./uac -p ir_triage $UACTMP &" | tee $UACTMP/uac-$HOSTNAME-$PLATFORM-run-$START_TIME.lis

# Ending UAC collection

echo "Ending UAC collection run at $(date +%Y-%m-%d-%H:%M:%S)"
echo "Listing file created '$UACTMP/uac-$HOSTNAME-$PLATFORM-run-$START_TIME.lis'"
echo "Please delete the UAC directory, UAC Collection and Log File when finished..."
