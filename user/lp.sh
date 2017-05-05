#!/bin/bash

SOCK=""
PROGRAM="./raxlpxs"
PATCH_FILE=""
PATCH_SHA1=""
COMMAND=""
SOCK=""

get_newest_qemu_sock() {
    SOCK="/var/run/sandbox/$(ls -t /var/run/sandbox/ | head -n1 )"
}

# assumes patch files are always in /var/opt/sandbox/
get_newest_patch_file() {
    PATCH_FILE=$(ls -t /var/opt/sandbox/*.raxlpxs | head -n1)
}

usage() {
    echo "$PROGRAM -c <apply | remove | info | find | list>"
    echo "	  [-f patch file]"
    echo "	  [-s patch sha1]"
    echo "	  [-h print this help message]"
    exit 1
}


while getopts "f:p:u:c:s:h" OPT; do
    case $OPT in
	p) PROGRAM=$OPTARG
	   ;;
	f) PATCH_FILE=$OPTARG
	   ;;
	u) PATCH_SHA1=$OPTARG
	   ;;
	c) COMMAND=$OPTARG
	   ;;
	s) SOCK=$OPTARG
	   ;;
	h) usage
	   ;;
	*) usage
	   ;;
    esac
done

if [[ -z $SOCK ]] ; then
      get_newest_qemu_sock
fi

if [[ -z $PATCH_FILE ]] ; then
   get_newest_patch_file
fi

case $COMMAND in
    apply) $PROGRAM --socket $SOCK --apply $PATCH_FILE
	   ;;
    info) $PROGRAM --socket $SOCK --info
	  ;;
    remove) $PROGRAM --socket $SOCK --remove $PATCH_SHA1
	    ;;
    find) $PROGRAM --socket $SOCK --find  $PATCH_SHA1
	  ;;
    list) $PROGRAM --socket $SOCK --list
	  ;;
    *) echo "invalid command option"; exit 1;;
esac
