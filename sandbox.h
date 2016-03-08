/***************************************************************
* Sandbox allows a user-space process to live-patch itself.
* Patches are placed in the "sandbox," which is a area in the
* .text segment
* 
* Copyright 2015-16 Rackspace, Inc.
***************************************************************/
#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <memory.h> 
#include <sys/mman.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

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

#ifdef X86_64
#define smp_mb()    ({ asm volatile("mfence" ::: "memory"); (void)0; })
#endif

#ifdef PPC64LE
#define smp_mb() {__asm__ __volatile__ ("sync" : : : "memory");}
#endif
typedef uint8_t * reloc_ptr_t;;



/* flags for patch list */
#define PATCH_APPLIED      0x01  // patch is applied
#define PATCH_IN_SANDBOX   0x02  // patch resident in sandbox area
#define PATCH_IS_DATA      0x04  // patch is modifying data
#define PATCH_WRITE_ONCE   0x08  // patch can be applied in one copy operation
#define PATCH_LIST_HDR     -1L;			\

//TODO: store the patch version in flags for each patch,
// return that info in reply messages.
// version of the sandbox interface is in the two high-order bytes
// of the flag 
#define SANDBOX_VERSION(f) (((uint64_t)(f) >> 0x38) & 0xff)

/* needs to be padded to an order of 2 */
/* TODO: align members on cache lines */
#define PATCH_PAD 0

/*****************************************************************
 *   STRUCT PATCH Members
 *  
 *  name: human-readable name for the patch
 *  SHA1: cryptographic signature of the patch data
 *  canary: an array of bytes that must match decoded instructions in 
 *         the patch target of the running binary.
 *  build_id: id of the binary to which this patch applies. This is intended
 *            to be a git commit # for the head of the repository when the 
 *            binary is built. 
 *  patch_dest: address of the patch once applied - a pointer 
 *              into the sandbox.
 *  reloc_dest: absolute address where the jump record, or trampoline, 
 *              is written.
 *  reloc_size: size in bytes of the jump record
 *  patch_buf: buffer containing patch bytes to be written to the sandbox.
 *  patch_size: the number of bytes in the patch, also the number 
 *              of bytes to be written to the sandbox, and the 
 *              size of the patch buffer.
 *  pad: empty bytes if needed for alignment purposes.
 ****************************************************************/
struct patch {
	struct patch *next;
	unsigned int flags;
	char  name[0x40];
	uint8_t SHA1[20];
	uint8_t canary[32];
	uint8_t build_id[20]; /* sha1 of git head when built */	
	uint8_t *patch_dest; /* absolute addr within the sandbox */
	uintptr_t reloc_dest; /* absolutre addr of the relocation */
	uint8_t reloc_data[PLATFORM_RELOC_SIZE]; /* max single instruction size is 15 */
	uint8_t reloc_size;
	uintptr_t patch_buf;  /* address of data to be patched */
	uint64_t patch_size;
	uint8_t pad[(PATCH_PAD)];
};


// these const strings contain information generated at build time.
extern const char *gitversion, *cc, *cflags;
extern uintptr_t patch_sandbox_start, patch_sandbox_end;
extern uint8_t *patch_cursor;
extern struct patch *patch_list;

uint8_t *make_sandbox_writeable(void);
struct patch *alloc_patch(char *name, uint64_t size);
void free_patch(struct patch *p);
int apply_patch(struct patch *new_patch);
void init_sandbox(void);
void dump_sandbox(const void* data, size_t size);

/* dl_iterate_phdr will call this function. */
int callback(struct dl_phdr_info *info, size_t size, void *data);

/* reflect - call this function to query the sandbox for the location
   of dynamic symbols.
   
   parameters
        struct dl_phdr_info *info   struct must contain a name or an address 
	   the sandbox will search using the name, address, or both
	int (*cb)(struct dl_phdr_info *info, size_t size, void *data), 
	   sandbox will

*/
int reflect(struct dl_phdr_info *info,
	    int (*cb)(struct dl_phdr_info *info, size_t, void *data));


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




// from sandbox-listen.h
ssize_t listen_sandbox_sock(const char *sock_name);
ssize_t accept_sandbox_sock(int listenfd, uid_t *uidptr);
ssize_t	readn(int fd, void *vptr, size_t n);
ssize_t writen(int fd, const void *vptr, size_t n);
ssize_t read_sandbox_message_header(int fd, uint16_t *version,
				    uint16_t *id, uint64_t *len);

