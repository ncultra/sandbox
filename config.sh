#!/bin/bash


echo "// platform definitions" > platform.h
echo "// this file is generated automatically by runing config.sh" >> platform.h

PAGESIZE=$(getconf PAGESIZE)

echo "#define PLATFORM_PAGE_SIZE $PAGESIZE" >> platform.h
echo "#define PLATFORM_RELOC_SIZE  0x04" >> platform.h
echo "#define PLATFORM_PAGE_MASK (~($(getconf PAGESIZE) - 1))" >> platform.h
echo "#define MAX_PATCH_SIZE $(getconf PAGESIZE)" >> platform.h

case $(uname -i) in
    "x86_64") 
    
	echo "#define X86_64 1" >> platform.h
	echo "#define PLATFORM_CACHE_LINE_SIZE 0x40" >> platform.h
	echo "#define PLATFORM_INSTRUCTION_DIVISOR 2" >> platform.h 

        ;;
    
    "ppc64le")
	echo "#define PPC64LE 1" >> platform.h
	echo "#define PLATFORM_CACHE_LINE_SIZE 0x80" >> platform.h
	echo "#define PLATFORM_INSTRUCTION_DIVISOR 0x10" >> platform.h        

	;;
    
esac
