/***************************************************************
 * Sandbox allows a user-space process to live-patch itself.
 * Patches are placed in the "sandbox," which is a area in the
 * .text segment
 *
 * Copyright 2015-17 Rackspace, Inc.
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
#include <sys/queue.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <libgen.h>
#include </usr/include/openssl/sha.h>
#include "platform.h"
#include "live_patch.h"
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

#define htoi(x) (isdigit(x) ? x-'0' : toupper(x)-'A'+10)

/* compatibility */

#define printk DMSG

static inline uintptr_t
___align (uintptr_t p, uintptr_t align)
{
  p += (align - 1);
  p &= ~(align - 1);
  return p;
}

#undef XEN_GUEST_HANDLE
#define XEN_GUEST_HANDLE(a) a

/*******************************************************************
 *  SANDBOX_ALLOC_SIZE
 *  determines the size of the static sandbox buffer
 *  must be page-aligned.
 */
#define SANDBOX_ALLOC_SIZE 0x100000

typedef uint8_t *reloc_ptr_t;


struct sandbox_header
{
  uint8_t *_start;
  uint8_t *_end;
  uint8_t *_cursor;
};

#define INFO_STRING_LEN 255
#define MAX_LIST_PATCHES 255	/* size of a list returned by __find_patch */
#define INFO_EXTRACT_LEN 32

#ifndef XEN_LIVEPATCH_PATCH_FILE_H_H
/* NOTE: defined externally in patch_file.h
 * must guarantee commonality with original struct definition
 */
struct check
{
  uintptr_t hvabs;
  uint16_t datalen;
  unsigned char *data;
};


struct function_patch
{
  char *funcname;
  uint64_t oldabs;
  uint32_t newrel;		//relative to beginning of function section in new obj.
};

struct table_patch
{
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

/* list head for applied patches */
struct lph
{
  struct applied_patch3 *lh_first;

};

struct patch_map
{
  void *addr;
  uint64_t size;
    LIST_ENTRY (patch_map) l;
};

struct applied_patch3
{
  struct patch_map map;
  unsigned char sha1[20];	/* binary encoded */
  uint32_t numwrites;
  struct xenlp_patch_write *writes;
  uint32_t numdeps;
  struct xenlp_hash *deps;
  char tags[MAX_TAGS_LEN];
    LIST_ENTRY (applied_patch3) l;
};

typedef struct xenlp_patch_info3 list_response;

#ifndef MAX_LIST_PATCHES
#define MAX_LIST_PATCHES 128
#endif

#ifndef INFO_STRING_LEN
#define INFO_STRING_LEN 255
#endif

/* these const strings contain information generated at build time. */
extern const char *gitversion, *cc, *cflags;
extern uintptr_t patch_sandbox_start, patch_sandbox_end;

extern uintptr_t patch_cursor;

extern struct lph lp_patch_head3;

void dump_sandbox (const void *data, size_t size);
uintptr_t ALIGN_POINTER (uintptr_t p, uintptr_t offset);

ptrdiff_t get_sandbox_free (void);

uintptr_t get_sandbox_start (void);
uintptr_t get_sandbox_end (void);

/* TODO: add a msg nonce (transaction id)
   from sandbox-listen.h
*/

/* TODO: re-index using NO_MSG_ID */
/* limit client requests per connection, to prevent DOS by a bad client */
#define SANDBOX_MSG_SESSION_LIMIT 0x64
#define SANDBOX_MSG_HDRLEN 0x10
#define SANDBOX_MSG_HBUFLEN 0x12
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
#define SANDBOX_MSG_UNDO_REQ                   9
#define SANDBOX_MSG_UNDO_REP                  10

#define SANDBOX_MSG_FIRST SANDBOX_MSG_APPLY
#define SANDBOX_MSG_LAST SANDBOX_MSG_UNDO_REP

#define SANDBOX_LAST_ARG -1	/* to terminate var args in buffer */
#define SANDBOX_MAX_ARG 0xff	/* maximum number of argumets to send a message */
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

/* *INDENT-OFF* */
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
/* *INDENT-ON* */


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

struct sandbox_buf
{
  uint32_t size;
  uint8_t *buf;
};

struct listen
{
  int sock;
  void *arg;
};

int set_debug (int db);
void DMSG (char *fmt, ...);
void LMSG (char *fmt, ...);
int init_sandbox (void);
pthread_t *run_listener (struct listen *l);
void *listen_thread (void *arg);
int listen_sandbox_sock (struct listen *);
int accept_sandbox_sock (int listenfd, uid_t * uidptr);
int cli_conn (char *sock_name);
ssize_t readn (int fd, void *vptr, size_t n);
ssize_t writen (int fd, const void *vptr, size_t n);
int read_sandbox_message_header (int fd, uint16_t * version,
				 uint16_t * id, uint32_t * len, void **buf);
int send_rr_buf (int fd, uint16_t id, ...);
void bin2hex (unsigned char *bin, size_t binlen, char *buf, size_t buflen);
int write_sandbox_message_header (int fd, uint16_t version, uint16_t id);
int xenlp_undo3 (XEN_GUEST_HANDLE (void *)arg);

/* **** test functions **** */
char *get_sandbox_build_info (int fd);
int client_func (void *p);
void *sandbox_list_patches (int fd);
int dispatch_list (int fd, int len, void **bufp);
int dispatch_list_response (int fd, int len, void **bufp);
int dispatch_apply (int fd, int len, void **bufp);
int dispatch_apply_response (int fd, int len, void **bufp);
int dispatch_getbld (int, int, void **);
int NO_MSG_ID (int, int, void **);
int dispatch_getbld_res (int fd, int len, void **);
int dispatch_test_req (int fd, int len, void **bufp);
int dispatch_test_rep (int, int len, void **);
int dispatch_undo_req (int fd, int len, void **bufp);
int dispatch_undo_rep (int fd, int len, void **bufp);
void hex2bin (char *buf, size_t buflen, unsigned char *bin, size_t binlen);
int do_lp_apply (int fd, void *buf, size_t buflen);
int xenlp_apply (void *arg);
int xenlp_apply3 (void *arg);

#endif /* __SANDBOX_H */
