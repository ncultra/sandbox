#!/usr/bin/env bash


oldifs=$IFS
IFS='.'

if  [[ ! -e $1 ]]; then
    echo "/* no version file */"
    exit 1
fi
read -ra VER < "$1"
MAJOR=${VER[0]}
MINOR=${VER[1]}
REVISION=${VER[2]}

echo "#define MAJOR_VERSION $MAJOR"
echo "#define MINOR_VERSION $MINOR"
echo "#define REVISION $REVISION"
echo "#define VERSION_STRING \"$MAJOR.$MINOR.$REVISION\""
IFS=$oldifs
