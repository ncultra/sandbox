/*****************************************************************
 * Copyright 2015 Rackspace, Inc.
 *
 * listen on a unix domain socket for incoming patches
 ****************************************************************/
#include "sandbox.h"


/*************************************************************************/
/*                 Message format                                        */
/*-----------------------------------------------------------------------*/
/*       0                   1                   2                   3   */
/*       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 */
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |     magic number:   0x53414e44  'SAND' in ascii                */
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      | protocol version              |   message id                  |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      | overall message length                                        |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |    4 bytes field 1 length                                     |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |    field  1                  ...                              |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |    4 bytes field n length                                     |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*      |    field  n                    ...                            |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/

#define SANDBOX_MSG_MAGIC 0x53414e44
#define SANDBOX_MSG_VERSION (uint16_t)0x01
#define SANDBOX_MSG_HDRLEN (uint16_t)0x44 
#define SANDBOX_MSG_GET_VER(b) (*(uint16_t *)((uint8_t *)b + 0x20))
#define SANDBOX_MSG_GET_ID(b) (*(uint16_t *)((uint8_t *)b + 0x30))
#define SANDBOX_MSG_MAX_LEN PLATFORM_PAGE_SIZE
#define SANDBOX_MSG_GET_LEN(b) (*(uint64_t *)((uint8_t *)b + 0x40))



#define SANDBOX_MSG_APPLY 1
#define SANDBOX_MSG_APPLYRSP 2
#define SANDBOX_MSG_LIST 3
#define SANDBOX_MSG_LISTRSP 4
#define SANDBOX_MSG_GET_BLD 5
#define SANDBOX_MSG_GET_BLDRSP 6

#define SANDBOX_OK 0
#define SANDBOX_ERR_BAD_HDR -2
#define SANDBOX_ERR_BAD_VER -3
#define SANDBOX_ERR_BAD_LEN -4
#define SANDBOX_ERR_BAD_MSGID -5
#define SANDBOX_ERR_NOMEM -6
#define SANDBOX_ERR_RW -7


/* Message ID 1: apply patch ********************************************/
/* Fields:
   1) header
   2) sha1 build id of the target - must match (20 bytes)
   3) patch name (string)
   4) canary (64 bytes of binary instructions), used to
      verify the jump address.
   5) jump location (uintptr_t  absolute address for jump)
   6) patch (bytes[patchlen] of instructions) destined for sandbox
   7) sha1 of the patch bytes (20 bytes)
   8) count of extended fields (4 bytes, always zero for this version).

   reply msg: ID 2
   1) header
   2) uint64_t  0L "OK," or error code
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
   1) header (msg id 3)

   reply msg ID 6:
   1) header
   2) uint64_t 0L "OK, or error code.
   3) 20-bytes sha1 git HEAD of the running binary
   4) $CC at build time (string)
   5) $CFLAGS at build time (string)
*/

ssize_t dispatch_apply(int, void **);
ssize_t dispatch_list(int, void **);
ssize_t dispatch_getbld(int, void **);
ssize_t dummy(int, void **);

typedef ssize_t (*handler)(int, void **);

handler dispatch[] =
{
	dispatch_apply,
	dummy,
	dispatch_list,
	dummy,
	dispatch_getbld,
	dummy,
	NULL
};

#define QLEN 5 // depth of the listening queue
#define STALE 30 // timout for client user id data

// WRS


// create and listen on a unix domain socket.
// connect, peek at the incoming data. 
// sock_name: full path of the socket e.g. /var/run/sandbox 
ssize_t listen_sandbox_sock(const char *sock_name)
{
	int fd, len, err, ccode;
	struct sockaddr_un un;

	if (strlen(sock_name) >= sizeof(un.sun_path)) {
		errno = ENAMETOOLONG;
		return(-1);
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		return(-2);
	}

	unlink(sock_name);

	memset( &un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, sock_name);  // already checked the length
	len = offsetof(struct sockaddr_un, sun_path) + strlen(sock_name);

	if (bind(fd, (struct sockaddr *)&un, len) < 0) {
		ccode = -3;
		goto errout;
	}

	if (listen(fd, QLEN) < 0) {
		ccode = -4;
		goto errout;
	}
errout:
	err = errno;
	close(fd);
	errno = err;
	return(ccode);
}


ssize_t accept_sandbox_sock(int listenfd, uid_t *uidptr)
{
	int clifd, err, ccode;
	socklen_t len;
	time_t staletime;
	struct sockaddr_un un;
	struct stat statbuf;
	char *name;

	if ((name = malloc(sizeof(un.sun_path + 1))) == NULL) {
		return (-1);
	}
	
	len = sizeof(un);
	do { clifd = accept(listenfd, (struct sockaddr *)&un, &len);
	} while (errno == EINTR || errno == EAGAIN);

	if (clifd < 0) {
		free(name);
		return (-2);
	}
	len -= offsetof(struct sockaddr_un, sun_path);
	memcpy(name, un.sun_path, len);
	name[len] = 0;
	if (stat(name, &statbuf) < 0) {
		ccode = -3; // couldn't stat the clients uid
		goto errout;
	}

	#ifdef S_ISSOCK
	if (S_ISSOCK(statbuf.st_mode) == 0) {
		ccode = -4;
		goto errout;
	}
	#endif

	// exit if the socket mode is too permissive or wrong
	if ((statbuf.st_mode & (S_IRWXG | S_IRWXO)) ||
	    (statbuf.st_mode & S_IRWXU) != S_IRWXU) {
		ccode = -5;
		goto errout;
	}

	// check the age of the socket access bits - it has to be active now
	staletime = time(NULL) - STALE;
	if (statbuf.st_atime < staletime ||
	    statbuf.st_ctime < staletime ||
	    statbuf.st_mtime < staletime) {
		ccode = -6;  // too old, not a currently active uid
		goto errout;
	}
	
	if (uidptr != NULL) {
		*uidptr = statbuf.st_uid;
	}

	unlink(name);
	free(name);
	return(clifd);

errout:
	err = errno;
	close(clifd);
	free(name);
	errno = err;
	return ccode;
}

// WRS, with check for Linux EAGAIN
ssize_t	readn(int fd, void *vptr, size_t n)
{
	size_t  nleft;
	ssize_t nread;
	char   *ptr;
	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				nread = 0;      /* and call read() again */
			else
				return (-1);
		} else if (nread == 0)
			break;              /* EOF */
		
		nleft -= nread;
		ptr += nread;
	}
	return (n - nleft);         /* return >= 0 */
}



// WRS, with check for Linux EAGAIN
ssize_t writen(int fd, const void *vptr, size_t n)
{
	size_t nleft;
	ssize_t nwritten;
	const char *ptr;
	
	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && (errno == EINTR || errno == EAGAIN))
				nwritten = 0;   /* and call write() again */
			else
				return (-1);    /* error */
		}
		
		nleft -= nwritten;
		ptr += nwritten;
	}
	return (n);
}

/* header is  3 * 32 bytes -
 * 'SAND'
 * version
 * id
 * overall message length
 */
/* if this function returns ERR, ptr parameters are undefined */
/* if it returns 0, ptr parameters will have correct values */
ssize_t read_sandbox_message_header(int fd, uint16_t *version,
				    uint16_t *id, uint64_t *len)
{
	uint8_t hbuf[0x60];
	ssize_t ccode = 0;
	void *dispatch_buffer = NULL;
	
	if ((ccode = readn(fd, &hbuf, sizeof(hbuf)) != sizeof(hbuf))) {x
		goto errout;
	}
	if ( *(uint32_t *)&hbuf[0] != SANDBOX_MSG_MAGIC) {
		ccode = SANDBOX_ERR_BAD_HDR;
		goto errout;
	}
	if (SANDBOX_MSG_VERSION != (*version = SANDBOX_MSG_GET_VER(hbuf))) {
		ccode = SANDBOX_ERR_BAD_VER;
		goto errout;
	}

	*id = SANDBOX_MSG_GET_VER(hbuf);
	
	if (*id < SANDBOX_MSG_APPLY || *id > SANDBOX_MSG_GET_BLDRSP) {
		ccode = SANDBOX_ERR_BAD_MSGID;
		goto errout;
	}

 	if (SANDBOX_MSG_MAX_LEN > (*len = SANDBOX_MSG_GET_LEN(hbuf))) {
		ccode = SANDBOX_ERR_BAD_LEN;
		goto errout;
	}
	ccode = dispatch[*id](fd, &dispatch_buffer);
	
errout:	
	return ccode;
	
}




ssize_t marshall_patch_data(int sock, void **bufp)
{
	assert(bufp && *bufp == NULL);

	/* alloc a big buffer (default is page size), then realloc it to be 
	 *  smaller after we copy the patch data. Then pass the buffer to
	 *  alloc_patch and it will be assigned as the buffer for the struct patch.
	 */
	
	if ((*bufp = calloc(sizeof(uint8_t),  PLATFORM_ALLOC_SIZE)) == NULL) {
		return SANDBOX_ERR_NOMEM;
	}
	
	uint8_t bldid[0x14], patch_sig[0x14], name[0x81], canary[0x40];
	uintptr_t jmpaddr;
	uint64_t len, patchlen;
	ssize_t ccode;

	/* target build id * - size must be 20 bytes */
	if (readn(sock, &len, sizeof(len)) == sizeof(len) && len == 0x14) {
		ccode = readn(sock, bldid, len);
		if (ccode != len) {
			ccode = SANDBOX_ERR_BAD_LEN;
			goto errout;
		}
	} else {
		ccode = SANDBOX_ERR_RW;
		goto errout;
	}
	
	//TODO: macro-ize this repitive code
	
	/* patch name, zero the buffer  */
	memset(name, 0x00, sizeof(name));
	if (readn(sock, &len, sizoef(len)) == sizeof(len)) {
		if (len > 0x80 || len < 0) {
			ccode = SANDBOX_ERR_BAD_LEN;
			goto errout;
		} 
		if (readn(sock, name, len) != len); {
			ccode = SANDBOX_ERR_RW;
			goto errout;
		}
	} else {
		ccode = SANDBOX_ERR_RW;
		goto errout;
	}

	/* patch canary, 64 bytes */

	if (readn(sock, &len, sizeof(len)) == sizeof(len) && len == 0x40) {
		if (readn(sock, canary, 0x40) != 0x40) {
			ccode  = SANDBOX_ERR_RW;
			goto errout;
		}	
	}  else {
		ccode = SANDBOX_ERR_RW;
		goto errout;
	}

	/* jump location */
	/* jmp location should be absolute when read here. the socket writer should have */
	/* added the location of _start to the relative offset. Then we check it using the canary. */
	/* The canary should be identical to 64 bytes starting at the jmp location (inclusively) */
	if (readn(sock, &len, sizeof(len)) == sizeof(len) && len == sizeof(uintptr_t)) {
		if (readn(sock, &jmpaddr, sizeof(uintptr_t)) != sizeof(uintptr_t)) {
			ccode = SANDBOX_ERR_RW;
			goto errout;
		}	
	}  else {
		ccode = SANDBOX_ERR_RW;
		goto errout;
	}
	
errout:

	free(*bufp);
	return ccode;
}



/*****************************************************************
 * Dispatch functions: at this point socket's file pointer 
 * is at the first field
 *
 *****************************************************************/
ssize_t dispatch_apply(int fd, void ** bufp)
{
	return(SANDBOX_OK);
}

ssize_t dispatch_list(int fd, void **bufp)
{
	return(SANDBOX_OK);
}

ssize_t dispatch_getbld(int fd, void **bufp)
{
	return(SANDBOX_OK);
}

ssize_t dummy(int fd, void **bufp)
{
	return(SANDBOX_ERR_BAD_HDR);
}


