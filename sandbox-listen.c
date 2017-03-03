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

 ssize_t check_magic(uint8_t *magic)
{
	uint8_t m[] = SANDBOX_MSG_MAGIC;

	return memcmp(magic, m, sizeof(m));
}



/* dispatch functions need to drain the socket buy reading all the bytes
 * in the message that follow the header */

/**************** declared in sandbox.h ***********************
 * ssize_t dispatch_apply(int, int, void **);
 * ssize_t dispatch_list(int, int, void **);
 * ssize_t dispatch_getbld(int, int, void **);
 * ssize_t dummy(int, int, void **);
 * ssize_t dispatch_getbld_res(int fd, int len, void **);
 * ssize_t dispatch_test_req(int fd, int len, void ** bufp);
 * ssize_t dispatch_test_rep(int, int len, void **);
 * ssize_t dispatch_undo_req(int fd, int len, void **bufp);
 * ssize_t dispatch_undo_rep(int fd, int len, void **bufp);
 *************************************************************/

typedef ssize_t (*handler)(int, int, void **);

handler dispatch[] =
{
	dummy, /* message ids are indexed starting at 1*/
	dispatch_apply,
	dispatch_apply_response,
	dispatch_list,
	dispatch_list_response,
	dispatch_getbld,
	dispatch_getbld_res,
	dispatch_test_req,
	dispatch_test_rep,
        dispatch_undo_req,
        dispatch_undo_rep,
	dummy,
        dummy
};

 int get_handler_count(void)
{
	return sizeof(dispatch) / sizeof(handler);
}


static int LISTEN_QUEUE_LEN = 5;
pthread_t *thr;

pthread_t *run_listener(struct listen *l){
	int ccode;
	DMSG("run_listener\n");
	thr = calloc(1, sizeof(pthread_t));
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

int should_stop = 0;

void stop_listener(pthread_t *which)
{
    if (thr == which)
        should_stop = 1;
}

void *listen_thread(void *arg)
{
	struct listen *l  = (struct listen *)arg;
	int quit = 0;
	int client_fd;
	uid_t client_id;
	char *listen_buf = NULL;

        DMSG("server_thread: listen.sock %d\n", l->sock);
	do {
            if (l->sock > 0) {
                client_fd = accept_sandbox_sock(l->sock, &client_id);
                if (client_fd < 0) {
                    DMSG("accept on %d failed with code %d\n", l->sock, client_fd);
                    DMSG("%s\n", strerror(errno));

                }
                while (client_fd > 0) {
                    uint16_t version, id;
                    uint32_t len;
                    quit   = read_sandbox_message_header(client_fd,
                                                         &version,
                                                         &id, &len,
                                                         (void **)&listen_buf);
                    if (quit == SANDBOX_ERR_CLOSED) {
                        DMSG("client closed socket %d\n", client_fd);
                        close(client_fd);
                        client_fd = -1;
                    }
                    else if (quit < 0) {
                        DMSG("error reading header %d\n", quit);
                    }
                    sched_yield();
                }
            } else {
                DMSG("bad socket value in listen thread\n");
                return NULL;
            }
	} while (!should_stop);
	if (client_fd >= 0)
            close(client_fd);
	return NULL;
}

/* WRS
// create and listen on a unix domain socket.
// connect, peek at the incoming data.
// sock_name: full path of the socket e.g. /var/run/SANDBOX_ERR_BAD_HDR
*/
int listen_sandbox_sock(struct listen *l)
{
	int len, err, ccode;
	struct sockaddr_un un;
	char sn[PATH_MAX];

	snprintf(sn, PATH_MAX, "%s%d", (char *)l->arg, (int)getpid());
	if ((l->sock  = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		return(-2);
	}
        if (l->arg)
            free(l->arg); 
        l->arg = strdup(sn);
	unlink(sn);
	DMSG("server socket %d: %s\n", l->sock, (char *)l->arg);
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	
	len = offsetof(struct sockaddr_un, sun_path) + strlen((char *)l->arg);
        strncpy(un.sun_path, (char *)l->arg, len);
        if (bind(l->sock, (struct sockaddr *)&un, len) < 0) {
		ccode = -3;
		goto errout;
	}
	if (listen(l->sock, LISTEN_QUEUE_LEN) < 0) {
		ccode = -4;
		goto errout;
	}
	DMSG("server now listening on %d %s\n", l->sock, (char *)l->arg);
	return l->sock;
errout:
	err = errno;
	close(l->sock);
	errno = err;
	return(ccode);
}

int accept_sandbox_sock(int listenfd, uid_t *uidptr)
{
    int clifd;
    socklen_t len;
    struct sockaddr_un un;

    len = sizeof(struct sockaddr_un);
    do {
        clifd = accept(listenfd, (struct sockaddr *)&un, &len);
    } while (errno == EINTR || errno == EAGAIN);

    if (clifd < 0) {
        return clifd;
    }

    DMSG("accept returning clifd %d\n", clifd);
    return(clifd);
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
	sprintf(un.sun_path, "%s", cpath);

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
        unlink(cpath);
	DMSG("connected\n");
	return s;
errout:
	if (should_unlink && (strlen(cpath) > 0)) {
		unlink(cpath);
	}
	return SANDBOX_ERR_BAD_FD;
}

/* WRS, with check for Linux EAGAIN */
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

/* WRS, with check for Linux EAGAIN */
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
	int i = 0;

	DMSG("reading sandbox messsge header...\n");
	DMSG("reading %d bytes from %d into %p\n", SANDBOX_MSG_HDRLEN, fd, hbuf);

	for (; i < SANDBOX_MSG_HDRLEN; i++) {
	 	if ((ccode = readn(fd, &hbuf[i], 1)) != 1) {
			if (ccode == 0) {
                            DMSG("read_sandbox_message_header: other party" \
                                 " closed the socket\n");
				return SANDBOX_ERR_CLOSED;
			}
			goto errout;
		}
	}
	dump_sandbox(hbuf, SANDBOX_MSG_HDRLEN);
	DMSG("checking magic ...\n");
	if (check_magic(hbuf)) {
		ccode = SANDBOX_ERR_BAD_HDR;
                DMSG("bad magic on message header\n");
                goto errout;
	}
	DMSG("checking protocol version...%d\n", SANDBOX_MSG_GET_VER(hbuf));
	if (SANDBOX_MSG_VERSION != (*version = SANDBOX_MSG_GET_VER(hbuf))) {
		ccode = SANDBOX_ERR_BAD_VER;
		goto errout;
	}
	*id = SANDBOX_MSG_GET_ID(hbuf);
	DMSG("reading message type: %d\n", *id);

	if (*id < SANDBOX_MSG_FIRST || *id > SANDBOX_MSG_LAST) {
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
	DMSG("read a bad or incomplete sandbox header\n");
	return SANDBOX_ERR_BAD_HDR;

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
		if (index > 0) {
			/* the first length field is included in the header,
			   don't count it but do count 1...n */
			len += sizeof(uint32_t);
		}
		len +=  bufs[index].size;

		index++;
	} while (index < 255);
	va_end(va);
	DMSG("last va arg index: %d, size %d\n", lastbuf, bufs[lastbuf].size);

        /* the length of the first bufsize is already calculated in
	   the header length. Further bufsizes (1...n) add the the
	   message length */

	DMSG("message length estimated to be %d bytes\n", len);
	if (len > SANDBOX_MSG_MAX_LEN) {
		DMSG("message calculated to exceed the maximum size\n");
		goto errout;
	}
	/* magic header */
	if (writen(fd, sand, sizeof(sand)) != sizeof(sand)) {
            DMSG("error writing response message header magic\n");
            goto errout;
        }
	/* protocol version */
	if (writen(fd, &pver, sizeof(uint16_t)) != sizeof(uint16_t)) {
            DMSG("error writing protocol version to header\n");
		goto errout;
	}
	/* message id  */
	if (writen(fd, &id, sizeof(uint16_t)) != sizeof(uint16_t)) {
            DMSG ("error writing message ID to header\n");
            goto errout;
        }
	/* msg length */
	if (writen(fd, &len, sizeof(uint32_t)) != sizeof(uint32_t)) {
            DMSG("error writing message length to header\n");
		goto errout;
        }
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
		dump_sandbox(bufs[index].buf, 16);
		writen(fd, &bufs[index].size, sizeof(uint32_t));
		DMSG("wrote var field size %d\n", bufs[index].size);
		writen(fd, bufs[index].buf, bufs[index].size);
		DMSG("wrote var field value\n");
	}
	return(SANDBOX_OK);
errout:
        DMSG("erring out of send_rr_buf\n");
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

	uint32_t ccode = SANDBOX_OK, remaining_bytes = len - SANDBOX_MSG_HDRLEN;;
	DMSG("apply patch dispatcher\n");

	if (remaining_bytes >= SANDBOX_MSG_MAX_LEN) {
		ccode = SANDBOX_ERR_PARSE;
		goto err_out;
	}

	uint8_t *patch_buf = calloc(remaining_bytes, sizeof(uint8_t));


	if (patch_buf == NULL) {

		ccode = SANDBOX_ERR_NOMEM;
		goto err_out;
	}


	if (readn(fd, patch_buf, remaining_bytes) == remaining_bytes) {
		DMSG("read incoming patch into the buffer...\n");
		dump_sandbox(patch_buf, 32);

		/* ccode = xenlp_apply(patch_buf); */
                ccode = xenlp_apply3(patch_buf);

	} else {
		ccode = SANDBOX_ERR_RW;
	}

/* allocate bufp and read the remainder of the message */
	err_out:
	send_rr_buf(fd, SANDBOX_MSG_APPLYRSP,
		    sizeof(ccode), &ccode,
		    SANDBOX_LAST_ARG);

	return ccode;
}


ssize_t dispatch_apply_response(int fd, int len, void **bufp)
{
	uint32_t response_code;

	if (readn(fd, &response_code, sizeof(response_code)) !=
	    sizeof(response_code))  {
		return SANDBOX_ERR_PARSE;
	}
	return response_code;

}


ssize_t dispatch_list(int fd, int len, void **bufp)
{
	int ccode = SANDBOX_ERR_PARSE;
	DMSG("patch list dispatcher\n");

/*	count the number of patches, then allocate list_response array
	struct list_response[];
*/
	list_response *r;
	struct list_head *xp;
	struct  applied_patch3 *ap;
	char *rbuf = NULL;

	uint32_t count = 0, current  = 0, rsize = 0;

	if (! list_empty(&lp_patch_head3))  {
		list_for_each(xp, &lp_patch_head3) {
			count++;
		}
		DMSG("applied patch list has %d patches\n", count);
		rsize = (count * sizeof(list_response)) + sizeof(uint32_t);
		DMSG("response buf size:  %d\n", rsize);

		rbuf = calloc(rsize, sizeof(uint8_t));
		if (rbuf == NULL) {
			DMSG("server out of memory processing patch list\n");
			return SANDBOX_ERR_NOMEM;
		}
		*(uint32_t *)rbuf = count;
		r = (list_response *)(rbuf + sizeof(uint32_t));


		list_for_each_entry(ap, &lp_patch_head3, l) {
			dump_sandbox(&ap->sha1, 20);
			memcpy(&r[current].sha1, ap->sha1, sizeof(ap->sha1));
			DMSG("reading %d patch sha1: \n", current);
			dump_sandbox(&r[current].sha1, 20);
                        r[current].hvaddr = (uint64_t)ap->blob;
			current++;
			if (current == count)
				break;
		}
		ccode = send_rr_buf(fd, SANDBOX_MSG_LISTRSP,
				   rsize, rbuf, SANDBOX_LAST_ARG);
		free(rbuf);
	} else {
		DMSG("applied patch list empty, sending null response list\n");
		DMSG(" %lx %p\n", sizeof(current), &current);

		ccode  = send_rr_buf(fd,
				     SANDBOX_MSG_LISTRSP,
				     sizeof(current), (uint8_t *)&current,
				     SANDBOX_LAST_ARG);
	}
	return ccode;
}



	/* allocates a response buffer using the clients double pointer */
	/* buffer will contain an array of struct list_response or NULL */
ssize_t dispatch_list_response(int fd, int len, void **bufp)
{
	int ccode, remaining_bytes = len - SANDBOX_MSG_HDRLEN;
	DMSG("patch list responder\n");

	*bufp = calloc(sizeof(uint8_t),
		       remaining_bytes + sizeof(list_response) + sizeof(uint32_t));
	if (*bufp  == NULL) {
		DMSG("error allocating buffer for patch list\n");
		return SANDBOX_ERR_NOMEM;
	}
	DMSG("allocated response buffer %p\n", *bufp);

	/* read the array of struct list_response into the buffer */
	/* terminated by a NULL entry */
	if ((ccode = readn(fd, *bufp, remaining_bytes) != remaining_bytes))  {

		DMSG("error reading list response buffer\n");
		/* safe way to free a buffer without checking for null */
		*bufp = realloc(*bufp, 0);
		*bufp = NULL;
		ccode = SANDBOX_ERR_PARSE;
	} else {
		DMSG("read list response buf, %d bytes\n", remaining_bytes);
		dump_sandbox(*bufp, 24);

		ccode = SANDBOX_OK;
	}

	return ccode;
}


ssize_t dispatch_getbld(int fd, int len, void **bufp)
{
/* construct a string buffer with each data on a separate line */
	int remaining_bytes = len - SANDBOX_MSG_HDRLEN;
	DMSG("striving for one and a half nines: remaining bytes %d\n", remaining_bytes);


	*bufp = calloc(sizeof(uint8_t), SANDBOX_MSG_BLD_BUFSIZE);
	if (*bufp  == NULL) {
		LMSG("error allocating buffer for build info\n");
		return SANDBOX_ERR_NOMEM;
	}
	snprintf(*bufp, SANDBOX_MSG_BLD_BUFSIZE, "%s\n%s\n%s\n%s\n%d.%d%d\n%s\n%s\n",
		 get_git_revision(),
		 get_compiled(),
                 get_ccflags(),
		 get_compiled_date(),
		 get_major(), get_minor(), get_revision(),
                 get_comment(),
                 get_sha1());

	uint32_t reply_buf_length = strnlen(*bufp, SANDBOX_MSG_BLD_BUFSIZE);
	DMSG("sending buildinfo reply %d bytes\n", reply_buf_length);

	return(send_rr_buf(fd, SANDBOX_MSG_GET_BLDRSP,
			   reply_buf_length, *bufp, SANDBOX_LAST_ARG));
}


/*** get build response msg
     HEADER
     uint32 first field size - length of buildinfo string
     uint8 *buildinfo
 ***/
ssize_t dispatch_getbld_res(int fd, int len, void **bufp)
{
	int remaining_bytes = len - SANDBOX_MSG_HDRLEN;

	DMSG("buildinfo response: remaining bytes = %d\n", remaining_bytes);
        /* get the buildinfo size */

	DMSG("field one size: %d, allocating\n", remaining_bytes);

	/* allocate a buffer to hold the buildinfo */
	*bufp = calloc(remaining_bytes + 1, sizeof(uint8_t));
	if (*bufp == NULL )
		return SANDBOX_ERR_NOMEM;

        /* read the buildinfo string into *bufp */

	if (readn(fd, *bufp, remaining_bytes) != remaining_bytes) {
		DMSG("buildinfo buffer unexpected size\n");
		return SANDBOX_ERR_RW;
	}

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
	DMSG("undo test  code: %d\n", code);

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



/*** undo request msg
     HEADER
     uint8_t[20] sha1
 ***/
ssize_t dispatch_undo_req(int fd, int len, void **bufp)
{

/*  reply = 0 for success, < 0 for not applied or error */
    uint32_t ccode;
    uint8_t sha1[20];
    char sha1_txt_buf[42];

    int remaining_bytes = len - SANDBOX_MSG_HDRLEN - sizeof(ccode);
    DMSG("undo request dispatcher: remaining bytes = %d\n", remaining_bytes);
    /* message should be 20 bytes sha1 of patch to undo */
    if (remaining_bytes != sizeof(sha1)) {
        DMSG("undo request wrong size: %d, not dispatched.\n", remaining_bytes);
        ccode =  SANDBOX_ERR_PARSE;
        goto exit;
    }

    if (readn(fd, &sha1[0], sizeof(sha1)) != sizeof(sha1)) {
        DMSG("error reading sha1 in undo message\n");
        ccode =  SANDBOX_ERR_RW;
        goto exit;
    }

    memset(sha1_txt_buf, 0x00, sizeof(sha1_txt_buf));
    bin2hex(sha1, sizeof(sha1), sha1_txt_buf, sizeof(sha1_txt_buf) - 1);
    DMSG("Undoing patch %s\n", sha1_txt_buf);
    ccode = xenlp_undo3(sha1);

exit:
    return(send_rr_buf(fd, SANDBOX_MSG_UNDO_REP, sizeof(uint32_t),
                       &ccode, SANDBOX_LAST_ARG));
}

/*** undo reply msg
     HEADER
     uint32_t return code
 ***/

ssize_t dispatch_undo_rep(int fd, int len, void **bufp)
{
    /* read remainder of message - ccode
       return ccode - 1 for success, 0 for not applied
     */

    	uint32_t c;
	DMSG("received an undo  reply - remaining bytes = %d\n", len - SANDBOX_MSG_HDRLEN);
	if (readn(fd, &c, sizeof(uint32_t)) != sizeof(uint32_t)) {
		DMSG("error reading undo reply message\n");
		return SANDBOX_ERR_RW;
	}
        return c;
}


ssize_t dummy(int fd, int len, void **bufp)
{
	DMSG("dummy dispatcher\n");
	return(send_rr_buf(fd, SANDBOX_ERR_BAD_MSGID, SANDBOX_ERR_BAD_MSGID,
			   SANDBOX_LAST_ARG));
}

/* info is returned as one string, with each field on a separate line */
char *get_sandbox_build_info(int fd)
{
	uint16_t version, id;
	uint32_t len;
	char *listen_buf = NULL, *info = NULL;

	if (send_rr_buf(fd, SANDBOX_MSG_GET_BLD, SANDBOX_LAST_ARG) == SANDBOX_OK) {
            DMSG("get_sandbox_build_info: fd %d\n", fd);

		read_sandbox_message_header(fd, &version, &id, &len, (void **)&listen_buf);
		if (listen_buf != NULL) {
			info = strndup((char *)listen_buf, SANDBOX_MSG_MAX_LEN);
			free(listen_buf);
		}
	}

	return info;
}

/* server will return with a block of sha1's that describes all the patches applied */
/* only need the sha1 of each patch */
/* work with struct xpatch (from xen live-patching) */
void  *sandbox_list_patches(int fd)
{
	uint16_t version, id;
	uint32_t len = 0L;
	char *listen_buf = NULL;
	int ccode;

	if (send_rr_buf(fd, SANDBOX_MSG_LIST, SANDBOX_LAST_ARG) == SANDBOX_OK) {
		ccode = read_sandbox_message_header(fd, &version, &id, &len,
						    (void **)&listen_buf);
		if (ccode || len < 0) {
			goto errout;
			dump_sandbox(listen_buf, 32);
		}

	}

	/* return buffer format:*/
        /* uint32_t count;
         *  struct list_response[count];
	 * buffer needs to be freed by caller
	*/
	return listen_buf;

errout:
        if (listen_buf != NULL) {
            free(listen_buf);
            listen_buf = NULL;
        }
        return NULL;
}


/* from xen-livepatch hypercall buffer
 * layout in memory:
 *
 * struct xenlp_apply
 * blob (bloblen)
 * relocs (numrelocs * uint32_t)
 * writes (numwrites * struct xenlp_patch_write)
 * struct xenlp_apply {
 *   unsigned char sha1[20];	SHA1 of patch file (binary)
 *   char __pad0[4];
 *   uint32_t bloblen;		Length of blob
 *   uint32_t numrelocs;		Number of relocations
 *   uint32_t numwrites;		Number of writes
 *   char __pad1[4];
 *   uint64_t refabs;		Reference address for relocations
 * };
 *
 * this is an analogue to the apply-patch hypercall for xen live patching.
*/

/* TODO: unwind the buffer and get a pointer to the blob */



