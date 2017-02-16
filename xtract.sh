#! /bin/bash

BUILD_ROOT="/home/mdday/src/QEMU"
BACK_FILE="$BUILD_ROOT/hmp.c.bak"
BUILD_FILE="$BUILD_ROOT/hmp.c"
XTRACT="/home/mdday/src/xen-livepatch/user/extract_patch"
PATCHED_OBJ="$BUILD_ROOT/hmp.o"
REF_FILE="/home/mdday/src/QEMU/x86_64-softmmu/qemu-system-x86_64-ref"
RUN_FILE="$BUILD_ROOT/x86_64-softmmu/qemu-system-x86_64"
ISO_FILE="$BUILD_ROOT/x86_64-softmmu/ttylinux-virtio_x86_64-16.1.iso"

# $1 is first file, $2 is 2nd file 
alternate_files() {
    pushd $BUILD_ROOT &>/dev/null
    RAND_FILE="$$.bak"
    cp $1 $RAND_FILE
    mv $2 $1
    mv $RAND_FILE $2
    popd &>/dev/null
}
                                    
alternate_ref_file() {
    pushd "$BUILD_ROOT/x86_64-softmmu" &>/dev/null
    alternate_files $RUN_FILE $REF_FILE
    popd &>/dev/null
}


# swaps exes and sources, then builds new exe
build_ref_file() {
    # copy runfile to ref, build new runfile
    alternate_files $BUILD_FILE $BACK_FILE
    alternate_files $RUN_FILE $REF_FILE
    pushd $BUILD_ROOT &>/dev/null
    # build the new run file
    rm $PATCHED_OBJ &>/dev/null    # force a rebuild of the relevant source
    qconf.sh --x86 --patch  --make
    pushd $BUILD_ROOT/sandbox/user
    make raxlpxs
    popd &>/dev/null
    popd &>/dev/null
}

# $1 is function name, $2 is new obj file, $3 is ref file 

 xtract_patch() {
     pushd $BUILD_ROOT &>/dev/null
     rm *.raxlpxs && rm sandbox/user/*.raxlpxs #&>/dev/null
     $XTRACT --qemu --function $1 $2 $3
     mv *.raxlpxs $BUILD_ROOT/sandbox/user
   popd &>/dev/null 
}

build_ref_file
xtract_patch hmp_info_version $PATCHED_OBJ $REF_FILE

#run ref qemu
#sudo $REF_FILE --monitor stdio --cdrom $ISO_FILE
