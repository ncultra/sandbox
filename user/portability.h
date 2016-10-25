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
               struct
               xenlp_patch_info **patch);

int do_lp_list(xc_interface_t xch, struct xenlp_list *list);

int _do_lp_buf_op_both(xc_interface_t xch, void *list, size_t buflen, uint64_t op);

unsigned int __attribute__((deprecated)) get_order_from_bytes(int len);

#endif /* __SANDBOX_PORT_H */
