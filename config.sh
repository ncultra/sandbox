#!/bin/bash



create_platform() {
    echo "// platform definitions" > platform.h
    echo "// this file is generated automatically by runing config.sh" >> platform.h

    PAGESIZE=$(getconf PAGESIZE)

    echo "#define PLATFORM_PAGE_SIZE $PAGESIZE" >> platform.h
    echo "#define PLATFORM_RELOC_SIZE  0x04" >> platform.h
    echo "#define PLATFORM_PAGE_MASK (~($(getconf PAGESIZE) - 1))" >> platform.h
    echo "#define MAX_PATCH_SIZE PLATFORM_PAGE_MASK" >> platform.h
    echo "#define PLATFORM_ALLOC_SIZE 0x1000" >> platform.h
    case $(uname -i) in
	"x86_64") 
	    
	    echo "#define X86_64 1" >> platform.h
	    echo "#define PLATFORM_CACHE_LINE_SIZE 0x40" >> platform.h
	    echo "#define PLATFORM_INSTRUCTION_DIVISOR 2" >> platform.h 

            ;;

	"i386")
	    echo "#define X86_32 1"  >> platform.h
	    echo "#define PLATFORM_CACHE_LINE_SIZE 0x20" >> platform.h
	    echo "#define PLATFORM_INSTRUCTION_DIVISOR 2" >> platform.h
	    ;;
	
	"ppc64le")
	    echo "#define PPC64LE 1" >> platform.h
	    echo "#define PLATFORM_CACHE_LINE_SIZE 0x80" >> platform.h
	    echo "#define PLATFORM_INSTRUCTION_DIVISOR 0x10" >> platform.h        

	    ;;
	
    esac
}


gen_version() {
    oldifs=$IFS
    IFS='.'
    if [[ ! -e $1 ]] ; then
	echo "/* no version file */" > version.mak
	exit 1
    fi

    read -ra VER<"$1"
    MAJOR=${VER[0]}
    MINOR=${VER[1]}
    REVISION=${VER[2]}
    echo "VERSION_STRING=\"$MAJOR.$MINOR.$REVISION\"" > version.mak
    echo "MAJOR_VERSION=$MAJOR" >> version.mak
    echo "MINOR_VERSION=$MINOR" >> version.mak
    echo "REVISION=$REVISION" >> version.mak
    IFS=$oldifs
    echo "GIT_REVISION=$(cd .. && git rev-parse HEAD), " >> version.mak	
    echo "GIT_TAG=$(cd .. && git describe --abbrev=0 --tags 2>/dev/null)" >> version.mak
}

until [[ -z "$" ]]; do
    case  "${1:0:2}" in "--")
	  case "${1:2:2}" in 
	      "ve") VER_FILE="${1##--ve*=}";
                    gen_version $VER_FILE
		    exit 0;;
	      "pl") create_platform; exit 0;;
	  esac ;;

	  *) create_platform; exit 0;;
    esac
done
