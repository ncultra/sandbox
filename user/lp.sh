#!/bin/bash


pushd ~/src/QEMU/sandbox/user &>/dev/null
SOCK="/var/run/sandbox/$(ls -t /var/run/sandbox/ | xargs | awk '{print $1}')"
FILE=$(ls -t ./*raxlpxs | xargs | awk '{print $1}')
./raxlpxs --socket $SOCK --apply $FILE
popd &>/dev/null
