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
typedef int* xc_interface_qemu;

typedef int xc_interface_t;
typedef int* xc_interface;

#define __HYPERVISOR_arch_2 SANDBOX_MSG_APPLY

int copy_from_guest(void *dest, int fd, int size);
int copy_to_guest(int fd, void *src, int size);

int open_xc(xc_interface_t *xch);
int do_xen_hypercall(xc_interface_t, void *);


int find_patch(xc_interface_t xch, unsigned char *sha1, size_t sha1_size,
               struct xenlp_patch_info **patch);

int do_lp_list(xc_interface_t xch, struct xenlp_list *list);
int do_lp_list3(xc_interface_t xch, struct xenlp_list3 *list);

int _do_lp_buf_op_both(xc_interface_t xch, void *list, size_t buflen, uint64_t op);
int _do_lp_buf_op(xc_interface_t xch, void *list, size_t buflen, uint64_t op);
unsigned int __attribute__((deprecated)) get_order_from_bytes(int len);

#define COUNT_INFO_STRINGS 6

#define INFO_SHA_INDEX 0
#define INFO_COMPILE_INDEX 1
#define INFO_FLAGS_INDEX 2
#define INFO_DATE_INDEX 3
#define INFO_TAG_INDEX 4
#define INFO_VER_INDEX 5
char info_strings[COUNT_INFO_STRINGS][INFO_STRING_LEN + 1];

#define INFO_CHECK(_sockfd)				\
	if (strnlen(info_strings[0], INFO_STRING_LEN) < 1)	\
		get_info_strings(_sockfd, 0);

int get_info_strings(int fd, int display);

static inline char * get_qemu_sha(int _sockfd)
{
	INFO_CHECK(_sockfd);
	return info_strings[INFO_SHA_INDEX];
}


static inline char * get_qemu_compile(int _sockfd)
{
	INFO_CHECK(_sockfd);
	return info_strings[INFO_COMPILE_INDEX];
}

static inline char * get_qemu_flags(int _sockfd)
{
	INFO_CHECK(_sockfd);
	return info_strings[INFO_FLAGS_INDEX];
}

static inline char * get_qemu_date(int _sockfd)
{
	INFO_CHECK(_sockfd);
	return info_strings[INFO_DATE_INDEX];	
}

static inline char * get_qemu_tag(int _sockfd)
{
	INFO_CHECK(_sockfd);
	return info_strings[INFO_TAG_INDEX];
}


static inline char *get_qemu_version(int _sockfd) 
{
	INFO_CHECK(_sockfd);
	return info_strings[INFO_VER_INDEX];
}


#endif /* __SANDBOX_PORT_H */
