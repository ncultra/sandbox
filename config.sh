#!/bin/bash


echo "// platform definitions" > platform.h
echo "// this file is generated automatically by runing config.sh" >> platform.h


case $(uname -i) in
    "x86_64") 
    
    echo "#define x86_64" >> platform.h
    echo "#define PLATFORM_PAGE_SIZE 0x1000" >> platform.h
    echo "#define PLATFORM_CACHE_LINE_SIZE 0x40" >> platform.h
    echo "#define PLATFORM_INSTRUCTION_DIVISOR 2" >> platform.h 
    echo "#define PLATFORM_RELOC_SIZE  0x04" >> platform.h
    echo "#define PLATFORM_PAGE_MASK ~(PLATFORM_PAGE_SIZE - 1)" >> platform.h
    echo "#define MAX_PATCH_SIZE PLATFORM_PAGE_SIZE" >> platform.h
    
    ;;
    
    "ppc64le") echo "//Open Power 64 Little Endian" >> platform.h
    echo "#define PLATFORM_PAGE_SIZE 0x1000" >> platform.h
    echo "#define PLATFORM_CACHE_LINE_SIZE 0x80" >> platform.h
    echo "#define PLATFORM_INSTRUCTION_DIVISOR 0x10" >> platform.h 
    echo "#define PLATFORM_RELOC_SIZE  0x04" >> platform.h
    echo "#define PLATFORM_PAGE_MASK ~(PLATFORM_PAGE_SIZE - 1)" >> platform.h
    echo "#define MAX_PATCH_SIZE PLATFORM_PAGE_SIZE" >> platform.h

	       
	       ;;
    
esac
