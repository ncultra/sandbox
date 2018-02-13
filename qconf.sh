#!/bin/bash

TARGET_LIST=""
BUILD_DIR="."
TRACE=""
OPTIONS=""
CHECK=0
MAKE=0
CONF=0
CLEAN=0
INSTALL=0
DRY_RUN=0
LIVE_PATCH=""

usage() {
    echo "qconf.sh --x86 or ppc  to configure for the x86 or ppc64 target only"
    echo "         --long to configure for x86, s390, ppc64 and arm targets"
    echo "         --med to configure for x86 and ppc64 targets"
    echo "         --trace to enable tracing with the simple backend"
    echo "               (trace will be logged to /var/log/trace.txt)"
    echo "         --all to configure for all targets (default)"
    echo "         --dir=<build directory>"
    echo "         --make  buld qemu"
    echo "         --check run make check"
    echo "         --clean run make clean"
    echo "         --install run make install"
    echo "         --patch build live patching library"
    echo "         --conf <options to pass to configure>"
    echo "         --dry-run print the configure command line and exit"
    echo "--conf must be last on the command line"
    exit 1
}

check_parms() {
    if (($CONF != 0 )) ; then
	return 0
    fi
    usage
}

until [ -z "$1" ]; do    
    case "${1:0:2}" in
        "--")
        case "${1:2:3}" in 
        "i386")CONF=1; TARGET_LIST="i386-softmmu";;
                
        "x86") CONF=1; TARGET_LIST="x86_64-softmmu";;
       "lon") CONF=1; 
		   TARGET_LIST="arm-softmmu,ppc64-softmmu,s390x-softmmu,x86_64-softmmu";;
	    "med") CONF=1; 
		   TARGET_LIST="ppc64-softmmu,x86_64-softmmu";;
	    "ppc") CONF=1; 
		   TARGET_LIST="ppc64-softmmu";;
	    "tra") CONF=1;
		   TRACE='--enable-trace-backend=simple --with-trace-file=trace.txt';;
            "all") CONF=1;;
	    "dir") BUILD_DIR="${1##--dir=}";;
            "hel") usage ;;
	    "che") CHECK=1;;
	    "cle") CLEAN=1;;
	    "ins") INSTALL=1;;
	    "mak") MAKE=1;;
	    "dry") DRY_RUN=1;;
	    "pat") LIVE_PATCH="--enable-livepatch";;
# "con" - configure options must be last on the command line
	    "con") shift; OPTIONS=$@;;
		
        esac ;;
        *)usage;;
    esac
        shift;
done

check_parms

if [ $DRY_RUN -ne 0 ] ; then
   echo "./configure --target-list=$TARGET_LIST $TRACE $LIVE_PATCH $OPTIONS"
   exit 1
fi


if [ $CONF -ne 0 ] ; then
    pushd $BUILD_DIR

# make sure we have the submodules

    if [ ! -f dtc/.git ] ; then 
	git submodule update --init dtc
    fi 

    if [ ! -f roms/SLOF/.git ] ; then 
	git submodule update --init roms/SLOF
    fi

    ./configure --target-list=$TARGET_LIST $TRACE $LIVE_PATCH $OPTIONS

# if we don't have the checkpatch hook installed, do it now
    if [ ! -f .git/hooks/pre-commit ] ; then
	(
	cat  <<'EOF'
#!/bin/bash
exec git diff --cached | scripts/checkpatch.pl --no-signoff -q -
EOF
        ) >> .git/hooks/pre-commit
	chmod 755 .git/hooks/pre-commit
    fi 
    popd

# if we don't have the commit-msg hook, add it now
    if [ ! -f .git/hooks/prepare-commit-msg ] ; then
	(
	cat <<'EOF'
SOB=$(git var GIT_AUTHOR_IDENT | sed -n 's/^\(.*>\).*$/Signed-off-by: \1/p')
grep -qs "^$SOB" "$1" || echo "$SOB" >> "$1"
EOF
	) >> .git/hooks/prepare-commit-msg
       chmod 755 .git/hooks/prepare-commit-msg
    fi
fi

if [ $CLEAN -ne 0 ] ; then
    pushd "$BUILD_DIR"
    make clean
    popd
fi

if [ $MAKE -ne 0 ] ; then
    pushd "$BUILD_DIR"
    make -j8
    popd
fi

if [ $INSTALL -ne 0 ] ; then
    pushd "$BUILD_DIR"
    sudo make install 
    popd
fi

if [ $CHECK -ne 0 ] ; then
    pushd "$BUILD_DIR"
    make check
    popd
fi
