#!/bin/bash

test() {
    pushd ~/src/QEMU/sandbox/user &>/dev/null
    SOCK="/var/run/sandbox/$(ls -t /var/run/sandbox/ | head -n1 )"
    FILE=$(ls -t ./*.raxlpxs | head -n1)
    #./raxlpxs --socket $SOCK --apply $FILE
    #./raxlpxs --socket $SOCK --info
    ./raxlpxs --socket $SOCK --remove "59dd0ad6af3fdd7f6aef27ef079964d9b007d7f4"
    popd &>/dev/null
}



SOCK=""
FILE=""
PROGRAM=$0
PATCH_FILE=""
PATCH_SHA1=""
COMMAND=""


get_newest_qemu_sock() {
    SOCK="/var/run/sandbox/$(ls -t /var/run/sandbox/ | head -n1 )"
}

# assumes patch files are always in /var/opt/sandbox/
get_newest_patch_file() {
    FILE=$(ls -t /var/opt/sandbox/*.raxlpxs | head -n1)
}

usage() {
    echo "$PROGRAM -c <apply | remove | info | find | list>"
    echo "        [-p patch file]"
    echo "        [-s patch sha1]"
    echo "        [-h print this help message]"
    exit 1
}


while getopts "p:s:c:h" OPT; do
    case $OPT in
	p) PATCH_FILE=$OPTARG
	   ;;
	s) PATCH_SHA1=$OPTARG
	   ;;
	c) COMMAND=$OPTARG
	   ;;
	h) usage
	   ;;
	*) usage
	   ;;
    esac
done

    echo -n "you chose "
    
case $COMMAND in
    apply) echo "apply";;
    info) echo "info";;
    remove) echo "remove";;
    find) echo "find";;
    list) echo "list";;
    *) echo "invalid command option"; exit 1;;
esac



