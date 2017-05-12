#! /bin/bash

# $1 is first file, $2 is 2nd file 
alternate_files()  {
    echo "$BUILD_ROOT"
    pushd "$BUILD_ROOT"&>/dev/null
    RAND_FILE="$$.bak"
    cp -f $1 $RAND_FILE
    mv -f $2 $1
    mv -f $RAND_FILE $2
    popd &>/dev/null
}
				    
alternate_ref_file() {
    pushd "$BUILD_ROOT/x86_64-softmmu" &>/dev/null
    echo "$RUN_FILE $REF_FILE"
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
    rm $PATCHED_OBJ &>/dev/null	   # force a rebuild of the relevant source
    ~/bin/qconf.sh --x86 --patch  --make
    pushd $BUILD_ROOT/sandbox/user
    make raxlpxs
    popd &>/dev/null
    popd &>/dev/null
}

# $1 is function name, $2 is new obj file, $3 is ref file 

 xtract_patch() {
     pushd "$BUILD_ROOT" &>/dev/null
     rm -f *.raxlcpxs &>/dev/null
     rm -f sandbox/user/*.raxlpxs &>/dev/null
     $XTRACT --qemu --function $1 $2 $3
     mv *.raxlpxs $BUILD_ROOT/sandbox/user
   popd &>/dev/null 
}


RUN_QEMU=0
CONFIG_FILE=""

usage() {
    echo "$PROGRAM --config=<config file>"
    echo "	     [--run]"
    exit 1
}

PROGRAM=$0


check_parms() {
    if ((${#CONFIG_FILE} != 0 )) ; then
	echo "${#CONFIG_FILE}"
	return 0
    fi
    usage
}


# currently other tools are assuming the patch directory\
# is /var/opt/sandbox, which is the default value for OPT_DIR 
# patch files are currently of the pattern *.raxlpx

mv_patch_files() {
    if [[ -e  $OPT_DIR ]] && [[ -d $OPT_DIR ]]
    then
	:
    else
	sudo mkdir $OPT_DIR
    fi
    sudo mv ./*.raxlpxs $OPT_DIR/
}


until [ -z "$1" ]; do	 
    case "${1:0:2}" in
	"--")
	case "${1:2:3}" in 
	    "run") RUN_QEMU=1;; 
	    "con") CONFIG_FILE="${1##--config=}";;
	    "hel") usage ;;
	esac ;;
	*)usage;;
    esac
	shift;
done

check_parms


echo "file $CONFIG_FILE"
echo "$RUN_QEMU"


typeset -A config # init array
config=( # set default values in config array
    [BUILD_ROOT]=""
    [BACK_FILE]=""
    [BUILD_FILE]=""
    [EXTRACT_PATCH]=""
    [PATCHED_OBJ]=""
    [REF_FILE]=""    #the exe that will be patched
    [RUN_FILE]=""    #the exe with the new code to generate the patch
    [ISO_FILE]=""    #the bootable image to run in qemu
    [OPT_DIR]="/var/opt/sandbox"
    [RUN_DIR]="/var/run/sandbox"
    [QCONF]=""
)


while read line
do
    if echo $line | grep -F = &>/dev/null
    then
	varname=$(echo "$line" | cut -d '=' -f 1)
	config[$varname]=$(echo "$line" | cut -d '=' -f 2-)
    fi
done < $CONFIG_FILE

export BUILD_ROOT=${config[BUILD_ROOT]} 
export BACK_FILE=${config[BUILD_ROOT]}${config[BACK_FILE]}
export BUILD_FILE=${config[BUILD_ROOT]}${config[BUILD_FILE]}
export EXTRACT_PATCH=${config[BUILD_ROOT]}${config[EXTRACT_PATCH]}
export PATCHED_OBJ=${config[BUILD_ROOT]}${config[PATCHED_OBJ]}
export REF_FILE=${config[BUILD_ROOT]}${config[REF_FILE]}
export RUN_FILE=${config[BUILD_ROOT]}${config[RUN_FILE]}
export ISO_FILE=${config[BUILD_ROOT]}${config[ISO_FILE]}
export RUN_DIR=${config[RUN_DIR]}
export OPT_DIR=${config[OPT_DIR]}

echo "BUILD_ROOT=${config[BUILD_ROOT]}"
echo "BACK_FILE=${config[BUILD_ROOT]}${config[BACK_FILE]}"
echo "BUILD_FILE=${config[BUILD_ROOT]}${config[BUILD_FILE]}"
echo "EXTRACT_PATCH=${config[BUILD_ROOT]}${config[EXTRACT_PATCH]}"
echo "PATCHED_OBJ=${config[BUILD_ROOT]}${config[PATCHED_OBJ]}"
echo "REF_FILE=${config[BUILD_ROOT]}${config[REF_FILE]}"
echo "RUN_FILE=${config[BUILD_ROOT]}${config[RUN_FILE]}"
echo "ISO_FILE=${config[BUILD_ROOT]}${config[ISO_FILE]}"
echo "RUN_DIR=${config[RUN_DIR]}"
echo "OPT_DIR=${config[OPT_DIR]}"


build_ref_file

$EXTRACT_PATCH --qemu --function hmp_info_version $PATCHED_OBJ $REF_FILE
mv_patch_files # creates /var/opt/sandbox if necessary, moves patch files

if (( $RUN_QEMU > 0 )); then
    pushd $BUILD_ROOT/x86_64-softmmu/
    sudo gdb $REF_FILE	--command gdbin.txt
    popd
fi
