/***************************************************************
* Sandbox allows a user-space process to live-patch itself.
* Patches are placed in the "sandbox," which is a area in the
* .text segment
* 
* Copyright 2015-16 Rackspace, Inc.
***************************************************************/

#include "../sandbox.h"
#include "portability.h"

int copy_from_guest(void *dest, XEN_GUEST_HANDLE(fd), int size)
{
    return readn(fd, dest, (size_t)size);
}

int copy_to_guest(XEN_GUEST_HANDLE(fd), void *src, int size)
{
    return writen(fd, src, (size_t)size);
    
}
