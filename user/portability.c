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

static char sockname[PATH_MAX];
static int sockfd;

/*******************************************************************
 * sandbox_name, AKA sockname, defines the path to the domain socket
 * that provides the other end of the live patching interface.
 * each QEMU instance will have a unique sandbox_name comprised of 
 * the path to the socket, and the owners process id
 ******************************************************************/

char *get_sandbox_name(void)
{
    return strdup(sockname);
    
}

void set_sandbox_name(char *name)
{
    strncpy(sockname, name, PATH_MAX);
}


/* use a wrapper function so we can eventually support other media beyond */
/* a domain socket, eg sysfs file */
int connect_to_sandbox(char *sandbox_name)
{
	return client_func(sandbox_name);	
}


/* TODO: use a weak alias to allow two different implementations of open_xc */
typedef int xc_interface_t;
int open_xc(xc_interface_t *xch)
{

    if (sockfd <= 0) {
        sockfd = connect_to_sandbox(sockname);
    }
    sockfd = connect_to_sandbox(sockname);

    *xch = sockfd;
    if (sockfd < 0) {
        printf("xc_interface_open failed\n");    
        return -1;
    }   
    return 0;
}
