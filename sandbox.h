/***************************************************************
* Sandbox allows a user-space process to live-patch itself.
* Patches are placed in the "sandbox," which is a area in the
* .text segment
* 
* Copyright 2015 Rackspace, Inc.
***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <memory.h> 
#include <sys/mman.h>
#include <errno.h>
#include <getopt.h>


#include <assert.h>
#include "platform.h"

// TODO: remove this def after we have a makefile
#ifndef __DEBUG__
#define __DEBUG__ 1
#endif

#ifdef __DEBUG__
#define DMSG(...) do {				\
		fprintf(stderr, __VA_ARGS__);	\
	} while ( 0 ) 	
#else
#define DMSG(...) do { } while( 0 )
#endif

// must be page-aligned.
#define SANDBOX_ALLOC_SIZE PLATFORM_PAGE_SIZE

#define smp_mb()    ({ asm volatile("mfence" ::: "memory"); (void)0; })

typedef uint8_t * reloc_ptr_t;;



/* flags for patch list */
#define PATCH_APPLIED      0x01  // patch is applied
#define PATCH_IN_SANDBOX   0x02  // patch resident in sandbox area
#define PATCH_IS_DATA      0x04  // patch is modifying data
#define PATCH_WRITE_ONCE   0x08  // patch can be applied in one copy operation

/* needs to be padded to an order of 2 */
/* TODO: align members on cache lines */
#define PATCH_PAD 0
struct patch {
	struct patch *next;
	unsigned int flags;
	char name[0x40];
	uint8_t SHA1[20];
	uint8_t *patch_dest; /* absolute addr within the sandbox */
	uintptr_t reloc_dest; /* absolutre addr of the relocation */
	uint8_t reloc_data[PLATFORM_RELOC_SIZE]; /* max single instruction size is 15 */
	uint8_t reloc_size;
	uintptr_t patch_buf;  /* address of data to be patched */
	uint64_t patch_size;
	uint8_t pad[(PATCH_PAD)];
};


extern uintptr_t patch_sandbox_start, patch_sandbox_end;
extern uint8_t *patch_cursor;
extern struct patch *patch_list;

uint8_t *make_sandbox_writeable(void);
struct patch *alloc_patch(char *name, uint64_t size);
void free_patch(struct patch *p);

int apply_patch(struct patch *new_patch);
void init_sandbox(void);
void dump_sandbox(const void* data, size_t size);
static inline uintptr_t ALIGN_POINTER(uintptr_t p, uintptr_t offset)
{
	p += (offset - 1);
	p &= ~(offset - 1);
	return p;
}


// offset should be  positive when adding a new patch, negative when removing a patch
static inline uint8_t *update_patch_cursor(uint64_t offset)
{
	return (patch_cursor += offset);
}

static inline void link_struct_patch(struct patch *p) 
{
	p->next = patch_list;
	patch_list = p;
};

static inline uint64_t get_sandbox_free(void)
{
	return ((uintptr_t)&patch_sandbox_end - (uintptr_t)patch_cursor);
}
