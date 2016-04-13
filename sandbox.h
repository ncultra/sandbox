/***************************************************************
* Sandbox allows a user-space process to live-patch itself.
* Patches are placed in the "sandbox," which is a area in the
* .text segment
* 
* Copyright 2015-16 Rackspace, Inc.
***************************************************************/
#define _GNU_SOURCE
#include <limits.h>
#include <string.h>
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
#include <libgen.h>
#include <openssl/sha.h>
#include "platform.h"



// TODO: remove move this def to the makefile
// TODO: incorporate a log level so this macro can log as well as diagnose bugs
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

/* list macros */

#define container_of(ptr, type, member) ({ \
                const typeof( ((type *)0)->member ) *__mptr = (ptr);  \
		(type *)( (char *)__mptr - offsetof(type,member) );})

struct list_node
{
	struct list_node *next, *prev;
};

struct list_head
{
	struct list_node n;
};

#define LIST_HEAD_INIT(name) { { &name.n, &name.n } }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void list_head_init(struct list_head *h)
{
	h->n.next = h->n.prev = &h->n;
}


static inline void list_node_init(struct list_node *n)
{
	n->next = n->prev = n;
}

static inline void list_add_after(struct list_head *h,
				   struct list_node *p,
				  struct list_node *n)

{
	n->next = p->next;
	n->prev = p;
	p->next->prev = n;
	p->next = n;
}


static inline void list_add(struct list_head *h,
			    struct list_node *n)

{
	list_add_after(h, &h->n, n);
}

static inline int list_empty_(const struct list_head *h)
{
	return h->n.next == &h->n;
}

static inline void list_del(struct list_node *n)
{
	n->next->prev = n->prev;
	n->prev->next = n->next;
}

#define list_entry(n, type, member) container_of(n, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member)			\
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member)                          \
         for (pos = list_first_entry(head, typeof(*pos), member);        \
              &pos->member != (head);                                    \
              pos = list_next_entry(pos, member))


// must be page-aligned.
#define SANDBOX_ALLOC_SIZE PLATFORM_PAGE_SIZE

#ifdef X86_64
#define smp_mb()    ({ asm volatile("mfence" ::: "memory"); (void)0; })
#endif

#ifdef PPC64LE
#define smp_mb() {__asm__ __volatile__ ("sync" : : : "memory");}
#endif
typedef uint8_t * reloc_ptr_t;


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

#define INFO_STRING_LEN 255
#define MAX_LIST_PATCHES 255

struct check {
    uint64_t hvabs;
    uint16_t datalen;
    unsigned char *data;
};


struct function_patch {
    char *funcname;
    uint64_t oldabs;
    uint32_t newrel;
};


struct table_patch {
    char *tablename;
    uint64_t hvabs;
    uint16_t datalen;
    unsigned char *data;
};


/*
 *
 * XENLP_apply (cmd 11)
 *
 */
#define XENLP_RELOC_UINT64	0	/* function dispatch tables, etc */
#define XENLP_RELOC_INT32	1	/* jmp instructions, etc */

struct xenlp_apply {
    unsigned char sha1[20];	/* SHA1 of patch file (binary) */
    char __pad0[4];
    uint32_t bloblen;		/* Length of blob */
    uint32_t numrelocs;		/* Number of relocations */
    uint32_t numwrites;		/* Number of writes */
    char __pad1[4];
    uint64_t refabs;		/* Reference address for relocations */
};

struct xenlp_patch_write {
    uint64_t hvabs;		/* Absolute address in HV to apply patch */

    unsigned char data[8];	/* 8-bytes of data to write at location */

    uint8_t reloctype;		/* XENLP_RELOC_ABS, XENLP_RELOC_REL */
    char dataoff;		/* Offset into data to apply relocation */

    char __pad[6];
};


struct xenlp_patch_info {
    uint64_t hvaddr;		/* virtual address in hypervisor memory */
    unsigned char sha1[20];	/* binary encoded */
    char __pad[4];
};


struct xenlp_list {
    uint16_t skippatches;	/* input, number of patches to skip */
    uint16_t numpatches;	/* output, number of patches returned */
    char __pad[4];
    struct xenlp_patch_info patches[MAX_LIST_PATCHES];	/* output */
};


struct xpatch {
	unsigned char sha1[20];	
	char xenversion[INFO_STRING_LEN]; /* qemu version, compiledate, etc */
	char xencompiledate[INFO_STRING_LEN]; 
	uint64_t crowbarabs; /* don't need this */
	uint64_t refabs; /* qemu start of .txt */
	uint32_t bloblen;
	unsigned char *blob;
	uint16_t numrelocs;
	uint32_t *relocs;
	uint16_t numchecks;  /*  not currently used */
	struct check *checks; /* same purpose as the canary in the classic patch struct */
	uint16_t numfuncs;
	struct function_patch *funcs;
	uint16_t numtables;
	struct table_patch *tables;
	struct list_node l; /* list handle */
};

/* this is the original QEMU patch format prior to converting to the raxlp tools. */
struct patch {
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
	struct list_node l;
	uint8_t pad[(PATCH_PAD)];
};


// these const strings contain information generated at build time.
extern const char *gitversion, *cc, *cflags;
extern uintptr_t patch_sandbox_start, patch_sandbox_end;
extern uint8_t *patch_cursor;

extern struct list_head patch_list;

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


static inline uint64_t get_sandbox_free(void)
{
	return ((uintptr_t)&patch_sandbox_end - (uintptr_t)patch_cursor);
}


uint64_t get_sandbox_start(void);
uint64_t get_sandbox_end(void);
// TODO: add a msg nonce (transaction id)
// from sandbox-listen.h
#define SANDBOX_MSG_HDRLEN 0x10
#define SANDBOX_MSG_HBUFLEN 0x18
#define SANDBOX_MSG_MAGIC  {'S', 'A', 'N', 'D'}
#define SANDBOX_MSG_VERSION (uint16_t)0x0001				      
#define SANDBOX_MSG_GET_VER(b) (*(uint16_t *)((uint8_t *)b + 4))
#define SANDBOX_MSG_GET_ID(b) (*(uint16_t *)((uint8_t *)b + 6))
#define SANDBOX_MSG_MAX_LEN PLATFORM_PAGE_SIZE
#define SANDBOX_MSG_GET_LEN(b) (*(uint32_t *)((uint8_t *)b + 8))
#define SANDBOX_MSG_PUT_LEN(b, l) ((*(uint32_t *)((uint8_t *)b + 8)) = (uint32_t)l)

#define SANDBOX_MSG_APPLY 1
#define SANDBOX_MSG_APPLYRSP 2
#define SANDBOX_MSG_LIST 3
#define SANDBOX_MSG_LISTRSP 4
#define SANDBOX_MSG_BLD_BUFSIZE 512
#define SANDBOX_MSG_GET_BLD 5
#define SANDBOX_MSG_GET_BLDRSP 6


#define SANDBOX_LAST_ARG -1
#define SANDBOX_TEST_REQ 0xfd
#define SANDBOX_TEST_REP 0xfe

#define SANDBOX_OK 0
#define SANDBOX_ERR_BAD_HDR -2
#define SANDBOX_ERR_BAD_VER -3
#define SANDBOX_ERR_BAD_LEN -4
#define SANDBOX_ERR_BAD_MSGID -5
#define SANDBOX_ERR_NOMEM -6
#define SANDBOX_ERR_RW -7
#define SANDBOX_ERR_BAD_FD -8
#define SANDBOX_ERR_CLOSED -9
#define SANDBOX_ERR_PARSE -10


/*************************************************************************/
/*                 Message format                                        */
/*-----------------------------------------------------------------------*/
/*       0                   1                   2                   3   */
/*       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 */
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |     magic number:   0x53414e44  'SAND' in ascii                */
/*      +-+-+-+-f+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      | protocol version              |   message id                  |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      | overall message length                                        |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |    4 bytes field 1 length                                     |<------- hdr ends here */
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |    field  1                  ...                              |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |    4 bytes field n length                                     |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |    field  n                    ...                            |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/



/* Message ID 1: apply patch ********************************************/
/* Fields:
   1) header
   2) sha1 build id of the target - must match (20 bytes)
   3) patch name (string)
   4) patch size
   5) patch buf
   6) canary (32 bytes of binary instructions), used to
      verify the jump address.
   7) jump location (uintptr_t  absolute address for jump)
   7) sha1 of the patch bytes (20 bytes)
   8) count of extended fields (4 bytes, always zero for this version).

   reply msg: ID 2
   1) header
   2) uint32_t  0L "OK," or error code
 */

/* Message ID 3: list patch ********************************************/
/* Fields:
   1) header
   2) patch name (string, wild cards ok)
   3) sha1 of the patch (corresponding to field 5 of message ID 1),
      20-byte buffer

   reply msg ID 4:
   1) header
   2) uint64_t 0L "OK, or error code.
   3) patch name (if found)
   4) sha1 of the patch
*/

/* Message ID 5: get build info ********************************************/

/* Fields:
   1) header (msg id 5)

   reply msg ID 6:
   1) header
   2) buildinfo contents 
*/

// TODO: add pid to socket name
#define SSANDBOX "sandbox-sock"

struct sandbox_buf {
	uint32_t size;
	uint8_t *buf;
};

struct listen 
{
	int sock;
	void *arg;
};

pthread_t *run_listener(struct listen *l);
void *listen_thread(void *arg);
int listen_sandbox_sock(const char *sock_name);
int accept_sandbox_sock(int listenfd, uid_t *uidptr);
int cli_conn(const char *sock_name);
ssize_t	readn(int fd, void *vptr, size_t n);
ssize_t writen(int fd, const void *vptr, size_t n);
ssize_t read_sandbox_message_header(int fd, uint16_t *version,
				    uint16_t *id, uint32_t *len, void **buf);
ssize_t send_rr_buf(int fd, uint16_t id, ...);
int write_sandbox_message_header(int fd,
				 uint16_t version, uint16_t id);
/* **** test functions **** */
char *get_sandbox_build_info(int fd);
int client_func(void *p);
int sandbox_list_patches(int fd);
int do_lp_apply(int fd, void *buf, size_t buflen);

