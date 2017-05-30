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


# currently other tools are assuming the patch directory
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

PROGRAM=$0
RUN_GDB=0
RUN_BAREMETAL=0
RUN_VALGRIND=0
RUN_NULL=0
RUN_DRY=0
BLD_REF=0
XTRACT=0
SHOW=0
CONFIG_FILE=""

check_parms() {
# must have at least a config file and a run option
    if ((${#CONFIG_FILE} != 0 )) ; then
	echo "config file ok"
	if (( ${#RUN_GDB} != 0 ||
		    ${#RUN_BAREMETAL} != 0 ||
		    ${RUN_VALGRIND} != 0 ||
		    ${RUN_DRY} != 0 ||
		    ${RUN_NULL} != 0)) ; then
	    return 0
	fi
    fi
    usage
    exit 1
}


usage() {
    echo "$PROGRAM --config=<config file>"
    echo "  [--gdb]  run under gdb"
    echo "  [--bare] run on baremetal"
    echo "  [--val]  run under valgrind"
    echo "  [--null] null target for rebuilds"
    echo "  [--dry]  dry run"
    echo "  [--build]  build the reference file"
    echo "  [--xtr]  extract the patch"
    echo "  [--sho]  show the config options"
    exit 1
}

#################### main script ###################

until [ -z "$1" ]; do	 
    case "${1:0:2}" in
	"--")
	    case "${1:2:3}" in 
		"con") CONFIG_FILE="${1##--config=}";;
		"gdb") RUN_GDB=1;;
		"bar") RUN_BAREMETAL=1;;
		"val") RUN_VALGRIND=1;;
		"nul") RUN_NULL=1;;
		"dry") RUN_DRY=1;;
		"bui") BLD_REF=1;;
		"xtr") XTRACT=1;;
		"sho") SHOW=1;;
		"hel") usage ;;
	    esac ;;
    esac
    shift;
done

check_parms

typeset -A config # init array
config=( # set default values in config array
    [BUILD_ROOT]=""
    [BACK_FILE]=""
    [BUILD_FILE]=""
    [EXTRACT_PATCH]=""
    [PATCHED_OBJ]=""
    [REF_FILE]=""    #the exe that wil be patched
    [RUN_FILE]=""    #the exe with the new code to generate the patch
    [ISO_FILE]=""    #the bootable image to run in qemu
    [OPT_DIR]="/var/opt/sandbox"
    [RUN_DIR]="/var/run/sandbox"
    [QCONF]=""
    [RUN_GDB_CMD]=""
    [RUN_BAREMETAL_CMD]=""
    [RUN_VALGRIND_CMD]=""
    [RUN_DRY_CMD]=""
    [RUN_NULL_CMD]='echo "run null"'
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
export RUN_DIR=${config[BUILD_ROOT]}${config[RUN_DIR]}
export OPT_DIR=${config[OPT_DIR]}
export QCONF=${config[BUILD_ROOT]}${config[QCONF]}
export RUN_GDB_CMD=${config[RUN_GDB_CMD]}
export RUN_BAREMETAL_CMD=${config[RUN_BAREMETAL_CMD]}
export RUN_VALGRIND_CMD=${config[RUN_VALGRIND_CMD]}
export RUN_NULL_CMD=${config[RUN_NULL_CMD]}
export RUN_DRY_CMD=${config[DRY_RUN]}

if (( SHOW > 0 )) ; then 
    echo "BUILD_ROOT=${config[BUILD_ROOT]}"
    echo "BACK_FILE=${config[BUILD_ROOT]}${config[BACK_FILE]}"
    echo "BUILD_FILE=${config[BUILD_ROOT]}${config[BUILD_FILE]}"
    echo "EXTRACT_PATCH=${config[BUILD_ROOT]}${config[EXTRACT_PATCH]}"
    echo "PATCHED_OBJ=${config[BUILD_ROOT]}${config[PATCHED_OBJ]}"
    echo "REF_FILE=${config[BUILD_ROOT]}${config[REF_FILE]}"
    echo "RUN_FILE=${config[BUILD_ROOT]}${config[RUN_FILE]}"
    echo "ISO_FILE=${config[BUILD_ROOT]}${config[ISO_FILE]}"
    echo "RUN_DIR=${config[BUILD_ROOT]}${config[RUN_DIR]}"
    echo "OPT_DIR=${config[OPT_DIR]}"
    echo "QCONF=${config[BUILD_ROOT]}${config[QCONF]}"
    echo "RUN_GDB_CMD=${config[RUN_GDB_CMD]}"
    echo "RUN_BAREMETAL_CMD=${config[RUN_BAREMETAL_CMD]}"
    echo "RUN_VALGRIND_CMD=${config[RUN_VALGRIND_CMD]}"
    echo "RUN_NULL_CMD=${config[RUN_NULL_CMD]}"
    echo "RUN_DRY_CMD=${config[RUN_DRY_CMD]}"
fi

if (( BLD_REF > 0 )) ; then
    if (( RUN_DRY > 0 )) ; then
	echo "dry run - build reference file selected"
    else
	build_ref_file
    fi
fi
if (( XTRACT > 0 )); then
    if (( RUN_DRY > 0 )) ; then
	echo "dry run - extract patch selected"
    else
	$EXTRACT_PATCH --qemu --function hmp_info_version $PATCHED_OBJ $REF_FILE
	mv_patch_files # creates /var/opt/sandbox if necessary, moves patch files
    fi
fi

### the order of run commands is:
### 1. dry
### 2. valgrind
### 3. baremetal
### 4. gdb
### the first run command that is set will execute, any others
### will not execute even if they are set

if (( RUN_DRY > 0 )); then
    pushd "$RUN_DIR" &> /dev/null
    $RUN_DRY_CMD
    popd &> /dev/null
    exit 0
fi

if (( RUN_NULL > 0 )); then
    pushd "$RUN_DIR" &> /dev/null
    $RUN_NULL_CMD
    popd &> /dev/null
    exit 0
fi

if (( RUN_VALGRIND > 0 )); then
    pushd "$RUN_DIR"
    $RUN_VALGRIND_CMD
    popd
    exit 0
fi

if (( RUN_BAREMETAL > 0 )); then
    pushd "$RUN_DIR"
    $RUN_BAREMETAL_CMD
    popd
    exit 0
fi

if (( RUN_GDB > 0 )); then
    pushd "$RUN_DIR"
    $RUN_GDB_CMD
    popd
    exit 0
fi

usage
exit 1
