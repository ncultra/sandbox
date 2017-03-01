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
#include <signal.h>
#include <sched.h>
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
#include <ctype.h>
#include <pthread.h>
#include <libgen.h>
#include "platform.h" 

#ifndef __SANDBOX_H
#define __SANDBOX_H 1


#define __max(a,b)                              \
    ({ __typeof__ (a) _a = (a);                 \
        __typeof__ (b) _b = (b);                \
        _a > _b ? _a : _b; })

#define __min(a,b)                              \
    ({ __typeof__ (a) _a = (a);                 \
        __typeof__ (b) _b = (b);                \
        _a < _b ? _a : _b; })


#define container_of(ptr, type, member) ({ \
                const typeof( ((type *)0)->member ) *__mptr = (ptr);  \
		(type *)( (char *)__mptr - offsetof(type,member) );})

#define htoi(x) (isdigit(x) ? x-'0' : toupper(x)-'A'+10)

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static __inline__ void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}


static __inline__ void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static __inline__ void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head->next);
}


/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static __inline__ void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */


#define LIST_POISON1 ((void *) 0x100)
#define LIST_POISON2 ((void *) 0x200)
static __inline__ void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static __inline__ void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}



/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static __inline__ int list_empty(const struct list_head *head)
{
	return head->next == head;
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/**
 * list_first_entry_or_null - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_prev_entry - get the prev element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)


/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = list_prev_entry(pos, member))

/**
 * list_prepare_entry - prepare a pos entry for use in list_for_each_entry_continue()
 * @pos:	the type * to use as a start point
 * @head:	the head of the list
 * @member:	the name of the list_head within the struct.
 *
 * Prepares a pos entry for use as a start point in list_for_each_entry_continue().
 */
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))



/* compatibility */

#define xmalloc(_type) ((_type *)aligned_alloc(__alignof__(_type), sizeof(_type)))
#define xfree(a) if(a) free(a)
#define printk DMSG

static inline uintptr_t ___align(uintptr_t p, uintptr_t align)
{ 
     p += (align - 1);
     p &= ~(align - 1);
     return p;
}

static inline void *aligned_zalloc(int align, int size)
{
    return  (void *)___align((uintptr_t)calloc(size + (align - 1), sizeof(char)), align);
}

#define xzalloc(_type) ((_type *)aligned_zalloc(__alignof__(_type), sizeof(_type)))


/* Allocate space for array of typed objects. */
#define xmalloc_array(_type, _num) \
    ((_type *)aligned_alloc(__alignof__(_type), sizeof(_type) * _num))


#define xzalloc_array(_type, _num) \
    ((_type *)aligned_zalloc(__alignof__(_type), sizeof(_type) * _num))

#undef XEN_GUEST_HANDLE
#define XEN_GUEST_HANDLE(a) a

/* must be page-aligned. */
#define SANDBOX_ALLOC_SIZE 0x100000

typedef uint8_t * reloc_ptr_t;


struct sandbox_header {
    uintptr_t _start;
    uintptr_t _end;
    uintptr_t _cursor;
};

struct sandbox_header *fill_sandbox(int);


#ifdef sandbox_port
#define INFO_STRING_LEN 255
#define MAX_LIST_PATCHES 1024 /* size of a list returned by __find_patch */

#endif


#ifndef XEN_LIVEPATCH_PATCH_FILE_H_H
/* NOTE: defined externally in patch_file.h 
 * must guarantee commonality with original struct definition
 */
struct check {
    uintptr_t hvabs;
    uint16_t datalen;
    unsigned char *data;
};


struct function_patch {
    char *funcname;
    uint64_t oldabs;
    uint32_t newrel;  //relative to beginning of function section in new obj.
};    
    
struct table_patch {
    char *tablename;
    uintptr_t hvabs;
    uint16_t datalen;
    unsigned char *data;
};

#endif 
/*
 *
 * XENLP_apply (cmd 11)
 *
 */
#define XENLP_RELOC_UINT64	0	/* function dispatch tables, etc */
#define XENLP_RELOC_INT32	1	/* jmp instructions, etc */

#define XENLP_CAPS_V3 0x1
#define MAX_TAGS_LEN	       128
#define MAX_LIST_DEPS            8
#define MAX_LIST_PATCHES3	16

struct applied_patch3 {
    void *blob;
    unsigned char sha1[20];		/* binary encoded */
    uint32_t numwrites;
    struct xenlp_patch_write *writes;
    uint32_t numdeps;
    struct xenlp_hash *deps;
    char tags[MAX_TAGS_LEN];
    struct list_head l;
};


/* NOTE: defined externally in patch_file.h 
 * must guarantee commonality with original struct definition
 */
struct xenlp_hash {
    unsigned char sha1[20];

    char __pad0[4];
};

struct xenlp_patch_write {
    uint64_t hvabs;		/* Absolute address in HV to apply patch */

    unsigned char data[8];	/* 8-bytes of data to write at location */

    uint8_t reloctype;		/* XENLP_RELOC_ABS, XENLP_RELOC_REL */
    char dataoff;		/* Offset into data to apply relocation */

    char __pad[6];
};

struct xenlp_patch_info3 {
    uint64_t hvaddr;		/* virtual address in hypervisor memory */
    unsigned char sha1[20];	/* binary encoded */
    char __pad[4];
    char tags[MAX_TAGS_LEN];
    struct xenlp_hash deps[MAX_LIST_DEPS];
};

struct xenlp_list3 {
    uint16_t skippatches;	/* input, number of patches to skip */
    uint16_t numpatches;	/* output, number of patches returned */
    char __pad[4];
    struct xenlp_patch_info3 patches[MAX_LIST_PATCHES3];	/* output */
};

typedef struct xenlp_patch_info3 list_response;

#ifndef MAX_LIST_PATCHES
#define MAX_LIST_PATCHES 128
#endif
/* layout in memory:
 *
 * struct xenlp_apply
 * blob (bloblen)
 * relocs (numrelocs * uint32_t)
 * writes (numwrites * struct xenlp_patch_write)
 * deps (numdeps * struct xenlp_dep)
 * tags (taglen) */
struct xenlp_apply3 {
    unsigned char sha1[20];	/* SHA1 of patch file (binary) */
    char __pad0[4];
    uint32_t bloblen;		/* Length of blob */
    uint32_t numrelocs;		/* Number of relocations */
    uint32_t numwrites;		/* Number of writes */
    char __pad1[4];
    uint64_t refabs;        /* Reference address for relocations */
    uint32_t numdeps;       /* Number of dependendencies */
    uint32_t taglen;        /* length of tags string */
};


struct xenlp_caps {
    uint64_t flags;
};

#ifndef INFO_STRING_LEN
#define INFO_STRING_LEN 255
#endif

/* these const strings contain information generated at build time. */
extern const char *gitversion, *cc, *cflags;
extern uintptr_t patch_sandbox_start, patch_sandbox_end; 

extern uintptr_t patch_cursor;

extern struct list_head lp_patch_head3;

uintptr_t  make_sandbox_writeable(void);
struct patch *alloc_patch(char *name, uint64_t size);
void free_patch(struct patch *p);
int apply_patch(struct patch *new_patch);
void init_sandbox(void);
void dump_sandbox(const void* data, size_t size);
uintptr_t ALIGN_POINTER(uintptr_t p, uintptr_t offset);

ptrdiff_t get_sandbox_free(void);

uintptr_t get_sandbox_start(void);
uintptr_t get_sandbox_end(void);

/* TODO: add a msg nonce (transaction id)
 from sandbox-listen.h
*/
#define SANDBOX_MSG_HDRLEN 0x10
#define SANDBOX_MSG_HBUFLEN 0x18
#define SANDBOX_MSG_MAGIC  {'S', 'A', 'N', 'D'}
#define SANDBOX_MSG_VERSION (uint16_t)0x0001				      
#define SANDBOX_MSG_GET_VER(b) (*(uint16_t *)((uint8_t *)b + 4))
#define SANDBOX_MSG_GET_ID(b) (*(uint16_t *)((uint8_t *)b + 6))
#define SANDBOX_MSG_MAX_LEN (MAX_PATCH_SIZE + SANDBOX_MSG_HDRLEN)
#define SANDBOX_MSG_GET_LEN(b) (*(uint32_t *)((uint8_t *)b + 8))
#define SANDBOX_MSG_PUT_LEN(b, l) ((*(uint32_t *)((uint8_t *)b + 8)) = (uint32_t)l)

#define SANDBOX_MSG_APPLY                      1
#define SANDBOX_MSG_APPLYRSP                   2
#define SANDBOX_MSG_LIST                       3
#define SANDBOX_MSG_LIST_BUFSIZE 512
#define SANDBOX_MSG_LISTRSP                    4
#define SANDBOX_MSG_GET_BLD                    5
#define SANDBOX_MSG_BLD_BUFSIZE 512
#define SANDBOX_MSG_GET_BLDRSP                 6
#define SANDBOX_TEST_REQ                       7
#define SANDBOX_TEST_REP                       8
#define SANDBOX_MSG_UNDO_REQ                   9
#define SANDBOX_MSG_UNDO_REP                  10

#define SANDBOX_MSG_FIRST SANDBOX_MSG_APPLY
#define SANDBOX_MSG_LAST SANDBOX_MSG_UNDO_REP

#define SANDBOX_LAST_ARG -1 /* to terminate var args in buffer */
#define SANDBOX_OK 0
#define SANDBOX_ERR -1
#define SANDBOX_ERR_BAD_HDR -2
#define SANDBOX_ERR_BAD_VER -3
#define SANDBOX_ERR_BAD_LEN -4
#define SANDBOX_ERR_BAD_MSGID -5
#define SANDBOX_ERR_NOMEM -6
#define SANDBOX_ERR_RW -7
#define SANDBOX_ERR_BAD_FD -8
#define SANDBOX_ERR_CLOSED -9
#define SANDBOX_ERR_PARSE -10
#define SANDBOX_ERR_INVALID -11
#define SANDBOX_SUCCESS 1

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
   5) address of patch blob in sandbox
*/

/* Message ID 5: get build info ********************************************/

/* Fields:
   1) header (msg id 5)

   reply msg ID 6:
   1) header
   2) buildinfo contents 
*/

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

int set_debug(int db);
void DMSG(char *fmt, ...);
void LMSG(char *fmt, ...);

pthread_t *run_listener(struct listen *l);
void *listen_thread(void *arg);
int listen_sandbox_sock(struct listen *);
int accept_sandbox_sock(int listenfd, uid_t *uidptr);
int cli_conn(char *sock_name);
ssize_t	readn(int fd, void *vptr, size_t n);
ssize_t writen(int fd, const void *vptr, size_t n);
ssize_t read_sandbox_message_header(int fd, uint16_t *version,
				    uint16_t *id, uint32_t *len, void **buf);
ssize_t send_rr_buf(int fd, uint16_t id, ...);
void bin2hex(unsigned char *bin, size_t binlen, char *buf,
                    size_t buflen);
int write_sandbox_message_header(int fd,
				 uint16_t version, uint16_t id);
int xenlp_undo3(XEN_GUEST_HANDLE(void *) arg);

/* **** test functions **** */
char *get_sandbox_build_info(int fd);
int client_func(void *p);
void *sandbox_list_patches(int fd);
ssize_t dispatch_list(int fd, int len, void **bufp);
ssize_t dispatch_list_response(int fd, int len, void **bufp);
ssize_t dispatch_apply(int fd, int len, void **bufp);
ssize_t dispatch_apply_response(int fd, int len, void **bufp);
ssize_t dispatch_getbld(int, int, void **);
ssize_t dummy(int, int, void **);
ssize_t dispatch_getbld_res(int fd, int len, void **);
ssize_t dispatch_test_req(int fd, int len, void ** bufp);
ssize_t dispatch_test_rep(int, int len, void **);
ssize_t dispatch_undo_req(int fd, int len, void **bufp);
ssize_t dispatch_undo_rep(int fd, int len, void **bufp);
void hex2bin(char *buf, size_t buflen, unsigned char *bin, size_t binlen);
int do_lp_apply(int fd, void *buf, size_t buflen);
int xenlp_apply(void *arg);
int xenlp_apply3(void *arg);

#endif /* __SANDBOX_H */
