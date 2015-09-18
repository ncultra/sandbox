/***************************************************************
* Sandbox allows a user-space process to live-patch itself.
* Patches are placed in the "sandbox," which is a area in the
* .text segment
* 
* Copyright 2015 Rackspace, Inc.
***************************************************************/

#define PLATFORM X86_64   // obtain using uname -i in the make file 
#if PLATFORM==X86_64
//  pages are always 4K for alignment purposes
#define PAGE_SIZE 0x1000
#define CACHE_LINE_SIZE 0x40
#define INSTRUCTION_OFFSET_DIVISOR 2 
#else
#error "platform constant are not defined"
#endif

#ifndef SANDBOX_ALLOC_SIZE
#define SANDBOX_ALLOC_SIZE 0x400
#endif

extern long long patch_sandbox_start, patch_sandbox_end;

#define PATCH_APPLIED_MASK 0x80  // leftmost bit
#define PATCH_IN_SANDBOX   0x40  // patch resident in sandbox area
#define PATCH_IS_DATA      0x20  // patch is modifying data
#define PATCH_WRITE_ONCE   0x10  // patch can be applied in one copy operation

//struct patch {
	
//}
	
