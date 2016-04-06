/*****************************************************************
 * Copyright 2015, 2016 Rackspace, Inc.
 *
 * listen on a unix domain socket for incoming patches
 ****************************************************************/
#include "sandbox.h"
#include "gitsha.h"

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
/*      |    4 bytes field 1 length                                     |*/
/*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <------- hdr ends here */
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
  
 the next field is one string with each field starting on a newline.
 Note: major, minor, revision are combined in one line

   3) 20-bytes sha1 git HEAD of the running binary,
     $CC at build time,
     $CFLAGS at build time,
     $compile_date,
     major version,
     minor version,
     revision
*/

static inline ssize_t check_magic(uint8_t *magic)
{
	uint8_t m[] = SANDBOX_MSG_MAGIC;
	
	return memcmp(magic, m, sizeof(m));
}



/* dispatch functions need to drain the socket buy reading all the bytes
 * in the message that follow the header */

static ssize_t marshal_patch_data(int, int, void **);
ssize_t dispatch_apply(int, int, void **);
ssize_t dispatch_list(int, int, void **);
ssize_t dispatch_getbld(int, int, void **);
ssize_t dummy(int, int, void **);
ssize_t dispatch_getbld_res(int fd, int len, void **);
ssize_t dispatch_test_req(int fd, int len, void ** bufp);
ssize_t dispatch_test_rep(int, int len, void **);


typedef ssize_t (*handler)(int, int, void **);

handler dispatch[0xff] =
{
	dummy, /* message ids are indexed starting at 1*/
	dispatch_apply,
	dummy,
	dispatch_list,
	dummy,
	dispatch_getbld,
	dispatch_getbld_res,
	[SANDBOX_TEST_REQ] = dispatch_test_req,
	[SANDBOX_TEST_REP] = dispatch_test_rep
};


#define QLEN 5 // depth of the listening queue
#define STALE 30 // timout for client user id data



pthread_t *run_listener(struct listen *l)
{
	int ccode;
	DMSG("run_listener\n");
	
	pthread_t *thr = calloc(1, sizeof(pthread_t));
	if (!thr)
		goto errout;
	
	if (!(ccode =
	      pthread_create(thr, NULL, listen_thread, (void *)l))) {
		DMSG("run_listener created thread %p\n", thr);
		return thr;
	}
	
	free(thr);		
errout:
	DMSG("run_listener_errout %d\n", ccode);
	return NULL;
}


// TODO: handle signals in the thread

void *listen_thread(void *arg)
{
	struct listen *l  = (struct listen *)arg;
	uint32_t quit = 0;
	int client_fd;
	uid_t client_id;
	char *listen_buf = NULL;

	/* TODO - need an inner loop to use the same socket with multiple messages. */

	DMSG("server_thread: listen.sock %d\n", l->sock);
	
	do {
		if (l->sock > 0) {	
			client_fd = accept_sandbox_sock(l->sock, &client_id);
			if (client_fd < 0) {
				DMSG("accept on %d failed\n", l->sock);
			}
			
			while (client_fd > 0) {
				uint16_t version, id;
				uint32_t len;
				quit   = read_sandbox_message_header(client_fd,
								     &version,
								     &id, &len,
								     (void **)&listen_buf);
				if (listen_buf != NULL) {
					free(listen_buf);
				}
			} 
			
		} else {
			DMSG("bad socket value in listen thread\n");
			return NULL;
		}
	} while (!quit && client_fd > 0);
		
	close(client_fd);
	return NULL;
}




// WRS
// create and listen on a unix domain socket.
// connect, peek at the incoming data. 
// sock_name: full path of the socket e.g. /var/run/SANDBOX_ERR_BAD_HDR

	int listen_sandbox_sock(const char *sock_name)
{
	int fd, len, err, ccode;
	struct sockaddr_un un;

	char sn[PATH_MAX];	
	
	
	if (strlen(sock_name) >= sizeof(un.sun_path) - 6 - 1) {
		errno = ENAMETOOLONG;
		return(-1);
	}
// use the short socket name during testing
//	sprintf(sn, "%s%d", sock_name, (int)getpid());
	sprintf(sn, "%s", sock_name);
	
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		return(-2);
	}
	unlink(sn);
	DMSG("server socket %d: %s\n", fd, sn);
	
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, sn);  // already checked the length
	len = offsetof(struct sockaddr_un, sun_path) + strlen(sn);

	if (bind(fd, (struct sockaddr *)&un, len) < 0) {
		ccode = -3;
		goto errout;
	}

	if (listen(fd, QLEN) < 0) {
		ccode = -4;
		goto errout;
	}
	DMSG("server now listening on %d %s\n", fd, sn);
	
	return fd;
errout:
	err = errno;
	close(fd);
	errno = err;
	return(ccode);
}


int accept_sandbox_sock(int listenfd, uid_t *uidptr)
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
	do {
		clifd = accept(listenfd, (struct sockaddr *)&un, &len);
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


int client_func(void *p)
{
	DMSG("client %d\n", getpid());

	char *spath = (char *)p;
	int s, len;
	int should_unlink = 0;
	
	struct sockaddr_un un, sun;
	char cpath[PATH_MAX];
	memset(cpath, 0, sizeof(cpath));
	sprintf(cpath, "%d", getpid());

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		DMSG("unable to get a socket\n");
			return SANDBOX_ERR_BAD_FD;
	}
	should_unlink = 1;
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	sprintf(un.sun_path, cpath);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
	unlink(un.sun_path);
	if (bind(s, (struct sockaddr *)&un, len) < 0) {
		DMSG("bind failed (client) %s\n", cpath);
		perror(NULL);
		goto errout;
	}

	if (chmod(un.sun_path, S_IRWXU) < 0) {
		DMSG("failed to set permissions %s\n", un.sun_path);
		perror(NULL);
		goto errout;	
	}
	
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, spath, sizeof(sun.sun_path));
	len = offsetof(struct sockaddr_un, sun_path) + strlen(spath);
	DMSG("client connecting to %s\n", spath);
	if (connect(s, (struct sockaddr *)&sun, len) < 0) {
		unlink(un.sun_path);
		DMSG("connect from %s failed\n", un.sun_path);
		perror(NULL);
		goto errout;
	}
	DMSG("connected\n");
	return s;
errout:
	if (should_unlink && (strlen(cpath) > 0)) {
		unlink(cpath);
	}
	
	return SANDBOX_ERR_BAD_FD;
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
			else {
				DMSG("errno: %d\n", errno);
				perror(NULL);
				return (-1);    /* error */
			}
			
		}
		
		nleft -= nwritten;
		ptr += nwritten;
	}
	return (n);
}

int write_sandbox_message_header(int fd, uint16_t version, uint16_t id)
{
	uint8_t magic[] = SANDBOX_MSG_MAGIC;
	uint32_t len = SANDBOX_MSG_HDRLEN;
	
	if (writen(fd, magic, sizeof(magic)) != sizeof(magic))
		goto errout;
	if (writen(fd, &version, sizeof(uint16_t)) != sizeof(uint16_t))
		goto errout;
	if (writen(fd, &id, sizeof(uint16_t)) != sizeof(uint16_t))
		goto errout;
	if (writen(fd, &len, sizeof(len)) != sizeof(len))
		goto errout;
	
	return SANDBOX_OK;
errout:
	return SANDBOX_ERR_RW;
}

/* header is  3 * 32 bytes -
 * 'SAND'
 * version
 * id
 * overall message length
 */
/* if this function returns ERR, ptr parameters are undefined */
/* if it returns 0, ptr parameters will have correct values */
/* void **buf is for the dispatch function to place data for the caller. */
/*  buf points to a pointer to null (*(void **)buf == NULL) */
ssize_t read_sandbox_message_header(int fd, uint16_t *version,
				    uint16_t *id, uint32_t *len,
				    void **buf)
{
/* TODO: reconsider buffer handling for this function. &len or len? */
/* allocate dispatch buffer or not? */
	uint8_t hbuf[SANDBOX_MSG_HBUFLEN];
	uint32_t ccode = 0;
	
	DMSG("reading sandbox messsge header...\n");
	DMSG("reading %d bytes from %d into %p\n", SANDBOX_MSG_HDRLEN, fd, hbuf);

	for (int i = 0; i < SANDBOX_MSG_HDRLEN; i++) {
		if ((ccode = readn(fd, &hbuf[i], 1)) != 1) {
			DMSG("error reading msg header\n");
			goto errout;
		}
		DMSG("%02x ", hbuf[i]);
	}	
	dump_sandbox(hbuf, SANDBOX_MSG_HDRLEN);
	
	DMSG("checking magic ...\n");
	if (check_magic(hbuf)) {
		ccode = SANDBOX_ERR_BAD_HDR;
		goto errout;
	}
	DMSG("checking protocol version...%d\n", SANDBOX_MSG_GET_VER(hbuf));
	if (SANDBOX_MSG_VERSION != (*version = SANDBOX_MSG_GET_VER(hbuf))) {
		ccode = SANDBOX_ERR_BAD_VER;
		goto errout;
	}

	*id = SANDBOX_MSG_GET_ID(hbuf);
	DMSG("reading message type: %d\n", *id);
	
	if (*id < SANDBOX_MSG_APPLY || *id > SANDBOX_TEST_REP) {
		ccode = SANDBOX_ERR_BAD_MSGID;
		goto errout;
	}

	DMSG("read header: msglen %d\n", SANDBOX_MSG_GET_LEN(hbuf));
	dump_sandbox(hbuf + 8, 4);
	
 	if (SANDBOX_MSG_MAX_LEN < (*len = SANDBOX_MSG_GET_LEN(hbuf))) {
		DMSG("max length: %d; this length:%d\n", SANDBOX_MSG_MAX_LEN, *len);
		ccode = SANDBOX_ERR_BAD_LEN;
		goto errout;
	}
	
	DMSG("dispatching...type %d\n",*id);
	ccode = dispatch[*id](fd, SANDBOX_MSG_GET_LEN(hbuf), buf);
	if (ccode == SANDBOX_OK)
		return ccode;
	
errout:
	DMSG("read a bad sandbox header\nb");
	
	return SANDBOX_ERR_BAD_HDR;
	
	
}




static ssize_t marshal_patch_data(int sock, int msg_len, void **bufp)
{
	assert(bufp && *bufp == NULL);

	
	uint8_t bldid[0x14];
	char name[0x81];
	uint64_t len, patchlen;
	ssize_t ccode;
	struct patch *new_patch = NULL;
	

	/* target build id * - size must be 20 bytes */
	//TODO - check the build id!
	if (readn(sock, &len, sizeof(len)) == sizeof(len) && len == 0x14) {
		ccode = readn(sock, bldid, len);
		if (ccode != len) {
			return(SANDBOX_ERR_BAD_LEN);
		}
	} else {
		return(SANDBOX_ERR_RW);
	}
	
	//TODO: macro-ize this repitive code

	if (readn(sock, &len, sizeof(len)) == sizeof(len)  && len < 0x40 && len < 0 ) {
		if (readn(sock, name, len) != len) {
			return(SANDBOX_ERR_RW);
		}
	}else {
		return(SANDBOX_ERR_BAD_LEN);	
	}
	
	/* patch data */


	if (readn(sock, &patchlen, sizeof(patchlen)) == sizeof(patchlen) &&
	    patchlen > 0 && patchlen < MAX_PATCH_SIZE) {
		new_patch = alloc_patch(name, patchlen);
		if (new_patch == NULL) {
			ccode = SANDBOX_ERR_NOMEM;
			goto errout;
		}
		assert(new_patch->patch_buf);
		if (readn(sock, (uint8_t *)new_patch->patch_buf, new_patch->patch_size) !=
		    new_patch->patch_size) {
			ccode = SANDBOX_ERR_RW;
			goto errout;
		}
	} else {
		ccode = SANDBOX_ERR_BAD_LEN;
		goto errout;
	}

	/* patch canary, 64 bytes */

	if (readn(sock, &len, sizeof(len)) == sizeof(len) && len == 0x20) {
		if (readn(sock, new_patch->canary, 0x20) != 0x20) {
			return(SANDBOX_ERR_RW);
		}	
	}  else {
		return(SANDBOX_ERR_BAD_LEN);
	}

	/* jump location */
	/* the socket writer will provide the relative jump location. we need to make */
	/*   it absolute by adding the start of the .text segment to the address. */
	/* Then we check it using the canary. The canary should be identical to */
        /*  64 bytes starting at the jmp location (inclusively) */

	if (readn(sock, &len, sizeof(len)) == sizeof(len) && len == sizeof(uintptr_t)) {
		if (readn(sock, &new_patch->reloc_dest, sizeof(uintptr_t)) !=
		    sizeof(uintptr_t)) {
			return(SANDBOX_ERR_RW);
		}	
	}  else {
		return(SANDBOX_ERR_BAD_LEN);
	}
	
	/* patch sha1 signature */
	if (readn(sock, &len, sizeof(len)) == 0x14) {
		// TODO: actually check the signature !
		if (readn(sock, new_patch->SHA1, 0x14) != 0X14) {
			ccode = SANDBOX_ERR_RW;
			goto errout;
		}
	} else {
		ccode = SANDBOX_ERR_BAD_LEN;
		goto errout;
	}
	
	new_patch->flags |= PATCH_WRITE_ONCE;
	memcpy(new_patch->build_id, bldid, 0x14);
	new_patch->reloc_size = PLATFORM_RELOC_SIZE;
	*bufp = new_patch;
	return(0L);
	
errout:
	if (new_patch != NULL) {
		free_patch(new_patch);
	}
	if (bufp && *bufp != NULL) {
		free(*bufp);
	}
	
	return send_rr_buf(sock, SANDBOX_ERR_BAD_HDR, sizeof(ccode), &ccode, SANDBOX_LAST_ARG);
	
}


	
ssize_t send_rr_buf(int fd, uint16_t id, ...)
{
	uint32_t len = SANDBOX_MSG_HDRLEN;
	uint8_t sand[] = SANDBOX_MSG_MAGIC;
	uint16_t pver = SANDBOX_MSG_VERSION;
	struct sandbox_buf bufs[255];
	va_list va;
	uint32_t nullsize = 0;
	
	int index = 0, lastbuf = 0;
	
	DMSG("send_rr_buf fd %d id %d\n", fd, id);

	va_start(va, id);
	do {
		bufs[index].size = va_arg(va, int);
		if (bufs[index].size == SANDBOX_LAST_ARG) {
			lastbuf = index;
			bufs[index].buf = (uint8_t *)&nullsize; 
			break;
		}
		bufs[index].buf = va_arg(va, uint8_t *);
		if (bufs[index].buf <= 0)
			break;
		len += sizeof(uint32_t) + bufs[index].size;
		
		index++;
	} while (index < 255);
	
	va_end(va);

	DMSG("last va arg index: %d\n", lastbuf);

	/* the length of the first bufsize is already calculated in 
	   the header length. Further bufsizes (1...n) add the the 
	   message length */
	
	DMSG("message length estimated to be %d bytes\n", len);	

	if (len > SANDBOX_MSG_MAX_LEN) {
		DMSG("message calculated to exceed the maximum size\n");
		goto errout;
	}
	
	/* magic header */
	if (writen(fd, sand, sizeof(sand)) != sizeof(sand))
			goto errout;

	/* protocol version */
	if (writen(fd, &pver, sizeof(uint16_t)) != sizeof(uint16_t))
		goto errout;
	
	/* message id  */
	if (writen(fd, &id, sizeof(uint16_t)) != sizeof(uint16_t))
		goto errout;

	/* msg length */
	if (writen(fd, &len, sizeof(uint32_t)) != sizeof(uint32_t))
		goto errout;

	DMSG("msg len at send time: %d\n", *&len);
	
/* go through the buf descriptors, this time write the values */
	
	for (index = 0; index < 255; index++) {
		if (bufs[index].size == SANDBOX_LAST_ARG) {
			assert(index == lastbuf);
			if (index == 0) {
				/* write for bytes of zero to complete the header */
				DMSG("writing null size to the message header, no varargs\n");
				writen(fd, &nullsize, sizeof(uint32_t));
			}
			break;
		}
		DMSG("writing vararg to fd size %d address %p\n",
		     bufs[index].size, bufs[index].buf);
		dump_sandbox(bufs[index].buf, bufs[index].size);
		
		writen(fd, &bufs[index].size, sizeof(uint32_t));
		writen(fd, bufs[index].buf, bufs[index].size);
	}
	return(SANDBOX_OK);
errout:
	return(SANDBOX_ERR_RW);
}

/*****************************************************************
 * Dispatch functions: at this point socket's file pointer 
 * is at the first field
 *
 *****************************************************************/
/* TODO - init message len field */
ssize_t dispatch_apply(int fd, int len, void **bufp)
{
	DMSG("apply patch dispatcher\n");

/* allocate bufp and read the remainder of the message */

	
	uint32_t ccode = marshal_patch_data(fd, len, bufp);
	if (ccode == SANDBOX_OK) {
		
		struct patch *p = (struct patch *)*bufp;
		ccode = apply_patch(p);
	}
	
	send_rr_buf(fd, SANDBOX_MSG_APPLYRSP, sizeof(ccode), &ccode, SANDBOX_LAST_ARG);
	return(ccode);
}

ssize_t dispatch_list(int fd, int len, void **bufp)
{
	DMSG("patch list dispatcher\n");
	return send_rr_buf(fd, SANDBOX_ERR_BAD_MSGID, SANDBOX_ERR_BAD_MSGID,
			   SANDBOX_LAST_ARG);
} 


/*****************************************************************
 * Dispatch functions: at this point socket's file pointer 
 * is at the first field
 *
 *****************************************************************/

ssize_t dispatch_getbld(int fd, int len, void **bufp)
{
/* construct a string buffer with each data on a separate line */
	uint32_t errcode = SANDBOX_OK;
	int remaining_bytes = len - SANDBOX_MSG_HDRLEN;
	DMSG("get bld info dispatcher: remaining bytes %d\n", remaining_bytes);

/* drain the request message from the socket */


	
	*bufp = calloc(sizeof(uint8_t), SANDBOX_MSG_BLD_BUFSIZE);
	if (*bufp  == NULL) {
		DMSG("error allocating buffer for build info\n");
		return SANDBOX_ERR_NOMEM;
	}
	snprintf(*bufp, SANDBOX_MSG_BLD_BUFSIZE, "%s\n%s\n%s\n%s\n%s\n%s\n%d %d %d\n",
		 get_git_revision(),
		 get_git_revision(), get_compiled(), get_ccflags(),
		 get_compiled_date(), get_tag(),
		 get_major(), get_minor(), get_revision());	

	return(send_rr_buf(fd, SANDBOX_MSG_GET_BLDRSP,
			   sizeof(uint32_t), &errcode,
			   SANDBOX_MSG_BLD_BUFSIZE, *bufp, SANDBOX_LAST_ARG));
}


ssize_t dispatch_getbld_res(int fd, int len, void **bufp)
{
	
	DMSG("dispatch_getbld_res\n");
// TODO fix this -  read the message size
	readn(fd, *bufp, SANDBOX_MSG_MAX_LEN);
	return SANDBOX_OK;	
}



ssize_t dispatch_test_req(int fd, int len, void ** bufp)
{
	int remaining_bytes = len - SANDBOX_MSG_HDRLEN;
	DMSG("test req dispatcher: remaining bytes = %d\n", remaining_bytes);
        /* message should be 4 byte test code (len of first field 
	   has already be read)*/

	uint32_t code;

	if (readn(fd, &code, sizeof(uint32_t)) != sizeof(uint32_t)) {
		DMSG("error reading test message\n");
		return SANDBOX_ERR_RW;
	}
	DMSG("%08x ", code);	
	dump_sandbox(&code, sizeof(code));
	printf("test code: %d\n", code);

	/* send a test response */
	return send_rr_buf(fd, SANDBOX_TEST_REP, sizeof(uint32_t),
			   &code, SANDBOX_LAST_ARG);
}

ssize_t dispatch_test_rep(int fd, int len, void **bufp)
{
	uint32_t c = 0xffffffff;
	DMSG("received a test response - remaining bytes = %d\n", len - SANDBOX_MSG_HDRLEN);
	if (readn(fd, &c, sizeof(uint32_t)) != sizeof(uint32_t)) {
		DMSG("error reading test message\n");
		return SANDBOX_ERR_RW;
	}
	printf("response code: %d\n", c);
	return SANDBOX_OK;
}


ssize_t dummy(int fd, int len, void **bufp)
{
	DMSG("dummy dispatcher\n");
	return(send_rr_buf(fd, SANDBOX_ERR_BAD_MSGID, SANDBOX_ERR_BAD_MSGID,
			   SANDBOX_LAST_ARG));	
}


char *get_sandbox_build_info(int fd)
{
	uint16_t version, id;
	uint32_t len;
	char *listen_buf = NULL, *info = NULL;
	
	send_rr_buf(fd, SANDBOX_MSG_GET_BLD, SANDBOX_LAST_ARG);
	read_sandbox_message_header(fd, &version, &id, &len, (void **)&listen_buf);
	if (listen_buf != NULL) {
		info =  strndup((char *)listen_buf, SANDBOX_MSG_MAX_LEN);
		free(listen_buf);
	}
	return info;
}
