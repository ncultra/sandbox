/***************************************************************
* Sandbox allows a user-space process to live-patch itself.
* Patches are placed in the "sandbox," which is a area in the
* .text segment
* 
* Copyright 2015-16 Rackspace, Inc.
***************************************************************/
#include <sys/socket.h>
#include <stdlib.h>
#include "../sandbox.h"
#include "../live_patch.h"
#ifndef __SANDBOX_PORT_H
#define __SANDBOX_PORT_H

#undef XENCTRL_HAS_XC_INTERFACE
typedef int xc_interface_t_qemu;
typedef int *xc_interface_qemu;

typedef int xc_interface_t;
typedef int *xc_interface;

#define __HYPERVISOR_arch_2 SANDBOX_MSG_APPLY

int connect_to_sandbox (char *sandbox_name);

int copy_from_guest (void *dest, int fd, int size);
int copy_to_guest (int fd, void *src, int size);

int open_xc (xc_interface_t * xch);
int do_xen_hypercall (xc_interface_t, void *);


int find_patch (xc_interface_t xch, unsigned char *sha1, size_t sha1_size,
		struct xenlp_patch_info3 **patch);
int __do_lp_list (xc_interface_t xch, struct xenlp_list3 *list);
int __do_lp_list3 (xc_interface_t xch, struct xenlp_list3 *list);
int __do_lp_caps (xc_interface_t xch, struct xenlp_caps *caps);
int __do_lp_apply (xc_interface_t xch, void *buf, size_t buflen);
int __do_lp_apply3 (xc_interface_t xch, void *buf, size_t buflen);
int __do_lp_apply4 (xc_interface_t xch, void *buf, size_t buflen);
int __do_lp_undo3 (xc_interface_t xch, void *buf, size_t buflen);

int __attribute__ ((deprecated)) _do_lp_buf_op_both (xc_interface_t xch,
						     void *list,
						     size_t buflen,
						     uint64_t op);
int __attribute__ ((deprecated)) _do_lp_buf_op (xc_interface_t xch,
						void *list, size_t buflen,
						uint64_t op);
unsigned int __attribute__ ((deprecated)) get_order_from_bytes (int len);

#define COUNT_INFO_STRINGS 7

#define INFO_GIT_INDEX 0
#define INFO_COMPILE_INDEX 1
#define INFO_FLAGS_INDEX 2
#define INFO_DATE_INDEX 3
#define INFO_VER_INDEX 4
#define INFO_COMMENT_INDEX 5
#define INFO_SHA1_INDEX 6

char info_strings[COUNT_INFO_STRINGS][INFO_STRING_LEN + 1];

#define INFO_CHECK(_sockfd)				\
	if (strnlen(info_strings[0], INFO_STRING_LEN) < 1)	\
		get_info_strings(_sockfd, 0);

int get_info_strings (int fd, int display);

static inline char *
get_qemu_git_index (int _sockfd)
{
  INFO_CHECK (_sockfd);
  return info_strings[INFO_GIT_INDEX];
}


static inline char *
get_qemu_compile (int _sockfd)
{
  INFO_CHECK (_sockfd);
  return info_strings[INFO_COMPILE_INDEX];
}

static inline char *
get_qemu_flags (int _sockfd)
{
  INFO_CHECK (_sockfd);
  return info_strings[INFO_FLAGS_INDEX];
}

static inline char *
get_qemu_date (int _sockfd)
{
  INFO_CHECK (_sockfd);
  return info_strings[INFO_DATE_INDEX];
}

static inline char *
get_qemu_version (int _sockfd)
{
  INFO_CHECK (_sockfd);
  return info_strings[INFO_VER_INDEX];
}

static inline char *
get_qemu_comment (int _sockfd)
{
  INFO_CHECK (_sockfd);
  return info_strings[INFO_COMMENT_INDEX];
}

static inline char *
get_qemu_sha1 (int _sockfd)
{
  INFO_CHECK (_sockfd);
  return info_strings[INFO_SHA1_INDEX];
}


#endif /* __SANDBOX_PORT_H */
