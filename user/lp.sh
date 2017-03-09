#!/bin/bash


pushd ~/src/QEMU/sandbox/user &>/dev/null
SOCK="/var/run/sandbox/$(ls -t /var/run/sandbox/ | xargs | awk '{print $1}')"
FILE=$(ls -t ./*.raxlpxs | head -n1)
#./raxlpxs --socket $SOCK --apply $FILE
#./raxlpxs --socket $SOCK --info
./raxlpxs --socket $SOCK --remove "59dd0ad6af3fdd7f6aef27ef079964d9b007d7f4"
popd &>/dev/null
