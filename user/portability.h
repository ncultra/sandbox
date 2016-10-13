/***************************************************************
* Sandbox allows a user-space process to live-patch itself.
* Patches are placed in the "sandbox," which is a area in the
* .text segment
* 
* Copyright 2015-16 Rackspace, Inc.
***************************************************************/
#include <sys/socket.h>

#ifndef __SANDBOX_PORT_H
#define __SANDBOX_PORT_H

#undef XEN_GUEST_HANDLE
#define XEN_GUEST_HANDLE(a) int a

int copy_from_guest(void *dest, int fd, int size);
int copy_to_guest(int fd, void *src, int size);

#endif /* __SANDBOX_PORT_H */
