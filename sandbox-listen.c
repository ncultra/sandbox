/*****************************************************************
 * Copyright 2015, 2016 Rackspace, Inc.
 *
 * listen on a unix domain socket for incoming patches
 ****************************************************************/
#include "sandbox.h"
#include "gitsha.h"

/*************************************************************************/
/*		   Message format					 */
/*-----------------------------------------------------------------------*/
/*	 0		     1			 2		     3	 */
/*	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 */
/*	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*	|     magic number:   0x53414e44  'SAND' in ascii		 */
/*	+-+-+-+-f+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
/*	| protocol version		| message id			|*/
/*	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*	| overall message length					|*/
/*	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*	|    4 bytes field 1 length					|*/
/*	++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ + <-- hdr ends here */
/*	|    field  1		       ...				|*/
/*	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*	|    4 bytes field n length					|*/
/*	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
/*	|    field  n			 ...				|*/
/*	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/

int
check_magic (uint8_t * magic)
{
    uint8_t m[] = SANDBOX_MSG_MAGIC;
    return memcmp (magic, m,
                   sizeof(m));
}

static int LISTEN_QUEUE_LEN = 5;
pthread_t *thr;

pthread_t *
run_listener (struct listen *l)
{
    int ccode;
    DMSG ("run_listener\n");
    thr = calloc (1, sizeof (pthread_t));
    if (!thr)
        goto errout;
    if (!(ccode = pthread_create (thr, NULL, listen_thread, (void *) l)))
    {
        DMSG ("run_listener created thread %p\n", thr);
        return thr;
    }
    free (thr);
errout:
    DMSG ("run_listener_errout %d\n", ccode);
    return NULL;
}

int should_stop = 0;

void
stop_listener (pthread_t * which)
{
    if (thr == which)
        should_stop = 1;
}

void *
listen_thread (void *arg)
{
    struct listen *l = (struct listen *) arg;
    int quit = 0;
    int client_fd;
    uid_t client_id;
    char *listen_buf = NULL;

    DMSG ("server_thread: listen.sock %d\n", l->sock);
    do
    {
        if (l->sock > 0)
	{
            client_fd = accept_sandbox_sock (l->sock, &client_id);
            if (client_fd < 0)
	    {
                DMSG ("accept on %d failed with code %d\n", l->sock, client_fd);
                DMSG ("%s\n", strerror (errno));

	    }
/* sched_yield is needed in the inner loop to prevent a DOS by a client flooding the server with request messages; the loop will keep reading messages until the client closes the socket. A bad client can send msg after msg after msg, ad infinutum. In addition to a yield, I think there should also be a counter to limit how many times through the inner loop the server will allow for a client.
 */
            int number_of_client_messages = 0;

            while (client_fd > 0 &&
                   number_of_client_messages < SANDBOX_MSG_SESSION_LIMIT)
	    {
                uint16_t version, id;
                uint32_t len;
                quit =
                    read_sandbox_message_header (client_fd,
                                                 &version,
                                                 &id, &len, (void **)
                                                 &listen_buf);
                if (quit == SANDBOX_ERR_CLOSED)
		{
                    DMSG ("client closed socket %d\n", client_fd);
                    close (client_fd);
                    client_fd = -1;
		}
                else if (quit < 0)
		{
                    DMSG ("error reading header %d\n", quit);
                    return NULL;
		}

                number_of_client_messages++;
                sched_yield ();
	    }
	}
        else
	{
            DMSG ("bad socket value in listen thread\n");
            return NULL;
	}
    }
    while (!should_stop);
    if (client_fd >= 0)
        close (client_fd);
    return NULL;
}

/* WRS
// create and listen on a unix domain socket.
// connect, peek at the incoming data.
// sock_name: full path of the socket e.g. /var/run/SANDBOX_ERR_BAD_HDR
*/
int
listen_sandbox_sock (struct listen *l)
{
    int len, err, ccode = SANDBOX_OK;
    struct sockaddr_un un;
    char sn[PATH_MAX];

    snprintf (sn, PATH_MAX, "%s%d", (char *) l->arg, (int) getpid ());
    if ((l->sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        return (-2);
    }
    if (l->arg)
        free (l->arg);
    l->arg = strdup (sn);
    unlink (sn);
    DMSG ("server socket %d: %s\n", l->sock, (char *) l->arg);
    memset (&un, 0, sizeof (un));
    un.sun_family = AF_UNIX;

    len = offsetof (struct sockaddr_un, sun_path) + strlen ((char *) l->arg);
    strncpy (un.sun_path, (char *) l->arg, len);
    if (bind (l->sock, (struct sockaddr *) &un, len) < 0)
    {
        ccode = EFAULT;
        goto errout;
    }
    if (listen (l->sock, LISTEN_QUEUE_LEN) < 0)
    {
        ccode = EIO;
        goto errout;
    }
    DMSG ("server now listening on %d %s\n", l->sock, (char *) l->arg);
    return l->sock;
errout:
    err = errno;
    close (l->sock);
    errno = err;
    return (ccode);
}


/*******************
 *   Error handling (accept man page)
 *   Linux accept() (and accept4()) passes already-pending network errors on
 *   the new socket as an  error code  from  accept().   This  behavior
 *   differs from other BSD socket implementations.  For reliable operation
 *   the application should detect the network errors defined for the protocol
 *   after  accept() and treat them like EAGAIN by retrying.  In the case of
 *   TCP/IP, these are ENETDOWN, EPROTO, ENOPRO‐TOOPT, EHOSTDOWN, ENONET,
 *  EHOSTUNREACH, EOPNOTSUPP, and ENETUNREACH.
 ****************/

int
accept_sandbox_sock (int listenfd, uid_t * uidptr)
{
    int clifd;
    socklen_t len;
    struct sockaddr_un un;

    len = sizeof (struct sockaddr_un);
    do
    {
        clifd = accept (listenfd, (struct sockaddr *) &un, &len);

    }
    while ((clifd == -1)
           && (errno == EINTR || errno == EAGAIN || EPERM || EACCES
               || EALREADY || EINPROGRESS || ETIMEDOUT));

    DMSG ("accept returning clifd %d\n", clifd);
    return (clifd);
}

/*
 *  a UNIX domain socket path is 108 bytes
 */
#define SUN_PATH_SIZE 108
int
client_func (void *p)
{
    DMSG ("client %d\n", getpid ());

    char *spath = (char *) p;
    int s, len;
    int should_unlink = 0;
    struct sockaddr_un un, sun;
    char cpath[SUN_PATH_SIZE];
    memset (cpath, 0, sizeof (cpath));
    sprintf (cpath, "%d", getpid ());

    if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        DMSG ("unable to get a socket\n");
        return SANDBOX_ERR_BAD_FD;
    }
    should_unlink = 1;
    memset (&un, 0, sizeof (un));
    un.sun_family = AF_UNIX;
    snprintf (un.sun_path, SUN_PATH_SIZE, "%s", cpath);

    len = offsetof (struct sockaddr_un, sun_path) + strlen (un.sun_path);
    unlink (un.sun_path);
    if (bind (s, (struct sockaddr *) &un, len) < 0)
    {
        DMSG ("bind failed (client) %s\n", cpath);
        perror (NULL);
        goto errout;
    }

    if (chmod (un.sun_path, S_IRWXU) < 0)
    {
        DMSG ("failed to set permissions %s\n", un.sun_path);
        perror (NULL);
        goto errout;
    }
    memset (&sun, 0, sizeof (sun));
    sun.sun_family = AF_UNIX;
    strncpy (sun.sun_path, spath, sizeof (sun.sun_path));
    len = offsetof (struct sockaddr_un, sun_path) + strlen (spath);
    DMSG ("client connecting to %s\n", spath);
    if (connect (s, (struct sockaddr *) &sun, len) < 0)
    {
        unlink (un.sun_path);
        DMSG ("connect from %s failed\n", un.sun_path);
        perror (NULL);
        goto errout;
    }
    unlink (cpath);
    DMSG ("connected\n");
    return s;
errout:
    if (should_unlink && (strlen (cpath) > 0))
    {
        unlink (cpath);
    }
    return SANDBOX_ERR_BAD_FD;
}

/* WRS, with check for Linux EAGAIN */
ssize_t
readn (int fd, void *vptr, size_t n)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;
    ptr = vptr;
    nleft = n;
    while (nleft > 0)
    {
        if ((nread = read (fd, ptr, nleft)) < 0)
	{
            if (errno == EINTR || errno == EAGAIN)
                nread = 0;		/* and call read() again */
            else
                return (-1);
	}
        else if (nread == 0)
            break;			/* EOF */

        nleft -= nread;
        ptr += nread;
    }
    return (n - nleft);		/* return >= 0 */
}

/* WRS, with check for Linux EAGAIN */
ssize_t
writen (int fd, const void *vptr, size_t n)
{
    size_t nleft;
    ssize_t nwritten;
    const char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0)
    {
        if ((nwritten = write (fd, ptr, nleft)) <= 0)
	{
            if (nwritten < 0 && (errno == EINTR || errno == EAGAIN))
                nwritten = 0;	/* and call write() again */
            else
	    {
                DMSG ("errno: %d\n", errno);
                perror (NULL);
                return (-1);	/* error */
	    }
	}
        nleft -= nwritten;
        ptr += nwritten;
    }
    return (n);
}

int
write_sandbox_message_header (int fd, uint16_t version, uint16_t id)
{
    uint8_t magic[] = SANDBOX_MSG_MAGIC;
    uint32_t len = SANDBOX_MSG_HDRLEN;

    if (writen (fd, magic, sizeof (magic)) != sizeof (magic))
        goto errout;
    if (writen (fd, &version, sizeof (uint16_t)) != sizeof (uint16_t))
        goto errout;
    if (writen (fd, &id, sizeof (uint16_t)) != sizeof (uint16_t))
        goto errout;
    if (writen (fd, &len, sizeof (len)) != sizeof (len))
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
int
read_sandbox_message_header (int fd, uint16_t * version,
			     uint16_t * id, uint32_t * len, void **buf)
{
    uint8_t hbuf[SANDBOX_MSG_HBUFLEN];
    uint32_t ccode = SANDBOX_OK;
    int i = 0;

    DMSG ("reading sandbox messsge header...\n");
    DMSG ("reading %d bytes from %d into %p\n", SANDBOX_MSG_HDRLEN, fd, hbuf);

    for (; i < SANDBOX_MSG_HDRLEN; i++)
    {
        if ((ccode = readn (fd, &hbuf[i], 1)) != 1)
	{
            if (ccode == 0)
	    {
                DMSG ("read_sandbox_message_header: other party"
                      " closed the socket\n");
                return SANDBOX_ERR_CLOSED;
	    }
            goto errout;
	}
    }
    dump_sandbox (hbuf, SANDBOX_MSG_HDRLEN);
    DMSG ("checking magic ...\n");
    if (check_magic (hbuf))
    {
        ccode = SANDBOX_ERR_BAD_HDR;
        DMSG ("bad magic on message header\n");
        goto errout;
    }
    DMSG ("checking protocol version...%d\n", SANDBOX_MSG_GET_VER (hbuf));
    if (SANDBOX_MSG_VERSION != (*version = SANDBOX_MSG_GET_VER (hbuf)))
    {
        ccode = SANDBOX_ERR_BAD_VER;
        goto errout;
    }
    *id = SANDBOX_MSG_GET_ID (hbuf);
    DMSG ("reading message type: %d\n", *id);

    if (*id < SANDBOX_MSG_FIRST || *id > SANDBOX_MSG_LAST)
    {
        ccode = SANDBOX_ERR_BAD_MSGID;
        goto errout;
    }

    DMSG ("read header: msglen %d\n", SANDBOX_MSG_GET_LEN (hbuf));
    dump_sandbox (hbuf + 8, 4);
    if (SANDBOX_ALLOC_SIZE < (*len = SANDBOX_MSG_GET_LEN (hbuf)))
    {
        DMSG ("max length: %d; this length:%d\n", SANDBOX_ALLOC_SIZE, *len);
        ccode = SANDBOX_ERR_BAD_LEN;
        goto errout;
    }
    DMSG ("dispatching...type %d\n", *id);
    switch (*id)
    {
    case SANDBOX_MSG_APPLY:
        ccode = dispatch_apply (fd, SANDBOX_MSG_GET_LEN (hbuf), buf);
        break;
    case SANDBOX_MSG_APPLYRSP:
        ccode = dispatch_apply_response (fd, SANDBOX_MSG_GET_LEN (hbuf), buf);
        break;

    case SANDBOX_MSG_LIST:
        ccode = dispatch_list (fd, SANDBOX_MSG_GET_LEN (hbuf), buf);
        break;
    case SANDBOX_MSG_LISTRSP:
        ccode = dispatch_list_response (fd, SANDBOX_MSG_GET_LEN (hbuf), buf);
        break;

    case SANDBOX_MSG_GET_BLD:
        ccode = dispatch_getbld (fd, SANDBOX_MSG_GET_LEN (hbuf), buf);
        break;
    case SANDBOX_MSG_GET_BLDRSP:
        ccode = dispatch_getbld_res (fd, SANDBOX_MSG_GET_LEN (hbuf), buf);
        break;

    case SANDBOX_MSG_UNDO_REQ:
        ccode = dispatch_undo_req (fd, SANDBOX_MSG_GET_LEN (hbuf), buf);
        break;
    case SANDBOX_MSG_UNDO_REP:
        ccode = dispatch_undo_rep (fd, SANDBOX_MSG_GET_LEN (hbuf), buf);
        break;
    default:
        close (fd);
        return SANDBOX_ERR_BAD_MSGID;
    }

    if (ccode == SANDBOX_OK)
        return ccode;
errout:
    DMSG ("read a bad or incomplete sandbox header\n");
    return ccode;
}




int
send_rr_buf (int fd, uint16_t id, ...)
{
    uint32_t len = SANDBOX_MSG_HDRLEN;
    uint8_t sand[] = SANDBOX_MSG_MAGIC;
    uint16_t pver = SANDBOX_MSG_VERSION;
    struct sandbox_buf bufs[255];
    va_list va;
    uint32_t nullsize = 0;
    int index = 0, lastbuf = 0;
    DMSG ("send_rr_buf fd %d id %d\n", fd, id);
    va_start (va, id);
    do
    {
        bufs[index].size = va_arg (va, int);
        if (bufs[index].size == SANDBOX_LAST_ARG)
	{
            lastbuf = index;
            bufs[index].buf = (uint8_t *) & nullsize;
            break;
	}
        bufs[index].buf = va_arg (va, uint8_t *);
        if (bufs[index].buf == 0)
            break;
        if (index > 0)
	{
            /* the first length field is included in the header,
               don't count it but do count 1...n */
            len += sizeof (uint32_t);
	}
        len += bufs[index].size;

        index++;
    }
    while (index < 255);
    va_end (va);
    if (index >= 255)
    {
        lastbuf = 255;
        bufs[lastbuf].size = SANDBOX_LAST_ARG;
        bufs[lastbuf].buf = (uint8_t *) & nullsize;
    }
    DMSG ("last va arg index: %d, size %d\n", lastbuf, bufs[lastbuf].size);

    /* the length of the first bufsize is already calculated in
       the header length. Futher bufsizes (1...n) add the the
       message length */

    DMSG ("message length estimated to be %d bytes\n", len);
    if (len > SANDBOX_ALLOC_SIZE)
    {
        DMSG ("message calculated to exceed the maximum size\n");
        goto errout;
    }
    /* magic header */
    if (writen (fd, sand, sizeof (sand)) != sizeof (sand))
    {
        DMSG ("error writing response message header magic\n");
        goto errout;
    }
    /* protocol version */
    if (writen (fd, &pver, sizeof (uint16_t)) != sizeof (uint16_t))
    {
        DMSG ("error writing protocol version to header\n");
        goto errout;
    }
    /* message id  */
    if (writen (fd, &id, sizeof (uint16_t)) != sizeof (uint16_t))
    {
        DMSG ("error writing message ID to header\n");
        goto errout;
    }
    /* msg length */
    if (writen (fd, &len, sizeof (uint32_t)) != sizeof (uint32_t))
    {
        DMSG ("error writing message length to header\n");
        goto errout;
    }
    DMSG ("msg len at send time: %d\n", *&len);

/* go through the buf descriptors, this time write the values */
    for (index = 0; index < 255; index++)
    {
        if (bufs[index].size == SANDBOX_LAST_ARG)
	{
            if (index == 0)
	    {
                /* write for bytes of zero to complete the header */
                DMSG ("writing null size to the message header, no varargs\n");
                writen (fd, &nullsize, sizeof (uint32_t));
	    }
            break;
	}
        DMSG ("writing vararg to fd size %d address %p\n",
              bufs[index].size, bufs[index].buf);
        dump_sandbox (bufs[index].buf, 16);
        writen (fd, &bufs[index].size, sizeof (uint32_t));
        DMSG ("wrote var field size %d\n", bufs[index].size);
        writen (fd, bufs[index].buf, bufs[index].size);
        DMSG ("wrote var field value\n");
    }
    return (SANDBOX_OK);
errout:
    DMSG ("erring out of send_rr_buf\n");
    return (SANDBOX_ERR_RW);
}

/*****************************************************************
 * Dispatch functions: at this point socket's file pointer
 * is at the first field
 *
 *****************************************************************/
/* TODO - init message len field */
int
dispatch_apply (int fd, int len, void **bufp)
{

    uint32_t ccode = SANDBOX_OK, remaining_bytes = len - SANDBOX_MSG_HDRLEN;;
    DMSG ("apply patch dispatcher\n");

    if (remaining_bytes >= SANDBOX_ALLOC_SIZE)
    {
        ccode = SANDBOX_ERR_PARSE;
        goto err_out;
    }

    uint8_t *patch_buf = calloc (remaining_bytes, sizeof (uint8_t));


    if (patch_buf == NULL)
    {

        ccode = SANDBOX_ERR_NOMEM;
        goto err_out;
    }


    if (readn (fd, patch_buf, remaining_bytes) == remaining_bytes)
    {
        DMSG ("read incoming patch into the buffer...\n");
        dump_sandbox (patch_buf, 32);

        /* ccode = xenlp_apply(patch_buf); */
        ccode = xenlp_apply3 (patch_buf);

    }
    else
    {
        ccode = SANDBOX_ERR_RW;
    }

err_out:
    send_rr_buf (fd, SANDBOX_MSG_APPLYRSP,
                 sizeof (ccode), &ccode, SANDBOX_LAST_ARG);
    free (patch_buf);

    return ccode;
}


int
dispatch_apply_response (int fd, int len, void **bufp)
{
    uint32_t response_code;

    if (readn (fd, &response_code, sizeof (response_code)) !=
        sizeof (response_code))
    {
        return SANDBOX_ERR_PARSE;
    }
    return response_code;

}


int
dispatch_list (int fd, int len, void **bufp)
{
    int ccode = SANDBOX_ERR_PARSE;
    DMSG ("patch list dispatcher\n");

/*	count the number of patches, then allocate list_response array
	struct list_response[];
*/
    list_response *r;
    struct list_head *xp;
    struct applied_patch3 *ap;
    char *rbuf = NULL;

    uint32_t count = 0, current = 0, rsize = 0;

    if (!list_empty (&lp_patch_head3))
    {
        list_for_each (xp, &lp_patch_head3)
        {
            count++;
        }
        DMSG ("applied patch list has %d patches\n", count);
        rsize = (count * sizeof (list_response)) + sizeof (uint32_t);
        DMSG ("response buf size:  %d\n", rsize);

        rbuf = calloc (rsize, sizeof (uint8_t));
        if (rbuf == NULL)
	{
            DMSG ("server out of memory processing patch list\n");
            return SANDBOX_ERR_NOMEM;
	}
        *(uint32_t *) rbuf = count;
        r = (list_response *) (rbuf + sizeof (uint32_t));


        list_for_each_entry (ap, &lp_patch_head3, l)
        {
            dump_sandbox (&ap->sha1, SHA_DIGEST_LENGTH);
            memcpy (&r[current].sha1, ap->sha1, SHA_DIGEST_LENGTH);
            DMSG ("reading %d patch sha1: \n", current);
            dump_sandbox (&r[current].sha1, SHA_DIGEST_LENGTH);
            r[current].hvaddr = (uint64_t) ap->blob;
            current++;
        }
        ccode = send_rr_buf (fd, SANDBOX_MSG_LISTRSP,
                             rsize, rbuf, SANDBOX_LAST_ARG);
        free (rbuf);
    }
    else
    {
        DMSG ("applied patch list empty, sending null response list\n");
        DMSG (" %lx %p\n", sizeof (current), &current);

        ccode = send_rr_buf (fd,
                             SANDBOX_MSG_LISTRSP,
                             sizeof (current),
                             (uint8_t *) & current, SANDBOX_LAST_ARG);
    }
    return ccode;
}



/* allocates a response buffer using the clients double pointer */
/* buffer will contain an array of struct list_response or NULL */
int
dispatch_list_response (int fd, int len, void **bufp)
{
    int ccode, remaining_bytes = len - SANDBOX_MSG_HDRLEN;
    DMSG ("patch list responder\n");

    *bufp = calloc (sizeof (uint8_t),
                    remaining_bytes + sizeof (list_response) +
                    sizeof (uint32_t));
    if (*bufp == NULL)
    {
        DMSG ("error allocating buffer for patch list\n");
        return SANDBOX_ERR_NOMEM;
    }
    DMSG ("allocated response buffer %p\n", *bufp);

    /* read the array of struct list_response into the buffer */
    /* terminated by a NULL entry */
    if ((ccode = readn (fd, *bufp, remaining_bytes) != remaining_bytes))
    {

        DMSG ("error reading list response buffer\n");
        /* safe way to free a buffer without checking for null */
        *bufp = realloc (*bufp, 0);
        *bufp = NULL;
        ccode = SANDBOX_ERR_PARSE;
    }
    else
    {
        DMSG ("read list response buf, %d bytes\n", remaining_bytes);
        dump_sandbox (*bufp, 24);

        ccode = SANDBOX_OK;
    }

    return ccode;
}


int
dispatch_getbld (int fd, int len, void **bufp)
{
/* construct a string buffer with each data on a separate line */

    char build_info_buffer[SANDBOX_MSG_BLD_BUFSIZE];

    int remaining_bytes = len - SANDBOX_MSG_HDRLEN;
    DMSG ("striving for one and a half nines: remaining bytes %d\n",
          remaining_bytes);

    snprintf (build_info_buffer, SANDBOX_MSG_BLD_BUFSIZE,
              "%s\n%s\n%s\n%s\n%d.%d%d\n%s\n%s\n",
              get_git_revision (),
              get_compiled (),
              get_ccflags (),
              get_compiled_date (),
              get_major (), get_minor (), get_revision (),
              get_comment (), get_sha1 ());

    uint32_t reply_buf_length =
        strnlen (build_info_buffer, SANDBOX_MSG_BLD_BUFSIZE);
    DMSG ("sending buildinfo reply %d bytes\n", reply_buf_length);

    /* write the buffer to the other end of the socket */
    /* build_info_buffer is persistent until after its written */
    /* to the socket */
    return (send_rr_buf (fd, SANDBOX_MSG_GET_BLDRSP,
                         reply_buf_length, build_info_buffer,
                         SANDBOX_LAST_ARG));
}



/*** get build response msg
     HEADER
     uint32 first field size - length of buildinfo string
     uint8 *buildinfo
***/
int
dispatch_getbld_res (int fd, int len, void **bufp)
{
    int remaining_bytes = len - SANDBOX_MSG_HDRLEN;

    DMSG ("buildinfo response: remaining bytes = %d\n", remaining_bytes);
    /* get the buildinfo size */

    DMSG ("field one size: %d, allocating\n", remaining_bytes);

    /* allocate a buffer to hold the buildinfo */
    *bufp = calloc (remaining_bytes + 1, sizeof (uint8_t));
    if (*bufp == NULL)
        return SANDBOX_ERR_NOMEM;

    /* read the buildinfo string into *bufp, caller frees the buf */

    if (readn (fd, *bufp, remaining_bytes) != remaining_bytes)
    {
        DMSG ("buildinfo buffer unexpected size\n");
        return SANDBOX_ERR_RW;
    }

    return SANDBOX_OK;
}

/*** undo request msg
     HEADER
     uint8_t[20] sha1
***/
int
dispatch_undo_req (int fd, int len, void **bufp)
{

/*  reply = 0 for success, < 0 for not applied or error */
    uint32_t ccode;
    uint8_t sha1[SHA_DIGEST_LENGTH];
    char sha1_txt_buf[(SHA_DIGEST_LENGTH * 2) + 2];

    int remaining_bytes = len - SANDBOX_MSG_HDRLEN - sizeof (ccode);
    DMSG ("undo request dispatcher: remaining bytes = %d\n", remaining_bytes);
    /* message should be 20 bytes sha1 of patch to undo */
    if (remaining_bytes != sizeof (sha1))
    {
        DMSG ("undo request wrong size: %d, not dispatched.\n",
              remaining_bytes);
        ccode = SANDBOX_ERR_PARSE;
        goto exit;
    }

    if (readn (fd, &sha1[0], SHA_DIGEST_LENGTH) != SHA_DIGEST_LENGTH)
    {
        DMSG ("error reading sha1 in undo message\n");
        ccode = SANDBOX_ERR_RW;
        goto exit;
    }

    memset (sha1_txt_buf, 0x00, sizeof (sha1_txt_buf));
    bin2hex (sha1, sizeof (sha1), sha1_txt_buf, sizeof (sha1_txt_buf) - 1);
    DMSG ("Undoing patch %s\n", sha1_txt_buf);
    ccode = xenlp_undo3 (sha1);

exit:
    return (send_rr_buf (fd, SANDBOX_MSG_UNDO_REP, sizeof (uint32_t),
                         &ccode, SANDBOX_LAST_ARG));
}

int
dispatch_undo_rep (int fd, int len, void **bufp)
{
    /* read remainder of message - ccode
       return ccode - 1 for success, 0 for not applied
    */

    uint32_t c;
    DMSG ("received an undo  reply - remaining bytes = %d\n",
          len - SANDBOX_MSG_HDRLEN);
    if (readn (fd, &c, sizeof (uint32_t)) != sizeof (uint32_t))
    {
        DMSG ("error reading undo reply message\n");
        return SANDBOX_ERR_RW;
    }
    return c;
}


int
NO_MSG_ID (int fd, int len, void **bufp)
{
    DMSG ("NO_MSG_ID dispatcher\n");
    return (send_rr_buf
            (fd, SANDBOX_ERR_BAD_MSGID, SANDBOX_ERR_BAD_MSGID,
             SANDBOX_LAST_ARG));
}

/********
 * info is returned as one string, with each field on a separate line
 * info is returned in a buffer allocated by the message handler,
 * simply pass a pointer to the buffer to the caller, avoiding an
 * extra copy.
 */
char *
get_sandbox_build_info (int fd)
{
    uint16_t version, id;
    uint32_t len;
    char *listen_buf = NULL;

    if (send_rr_buf (fd, SANDBOX_MSG_GET_BLD, SANDBOX_LAST_ARG) == SANDBOX_OK)
    {
        DMSG ("get_sandbox_build_info: fd %d\n", fd);
        read_sandbox_message_header (fd, &version, &id, &len,
                                     (void **) &listen_buf);
    }
    return listen_buf;
}

/* server will return with a block of sha1's that describes all the patches applied */
/* only need the sha1 of each patch */
/* work with struct xpatch (from xen live-patching) */
void *
sandbox_list_patches (int fd)
{
    uint16_t version, id;
    uint32_t len = 0L;
    char *listen_buf = NULL;
    int ccode;

    if (send_rr_buf (fd, SANDBOX_MSG_LIST, SANDBOX_LAST_ARG) == SANDBOX_OK)
    {
        ccode =
            read_sandbox_message_header (fd, &version, &id, &len,
                                         (void **) &listen_buf);
        if (ccode || !len)
	{
            dump_sandbox (listen_buf, 32);
            goto errout;
	}
    }

    /* return buffer format:
     * uint32_t count;
     * struct list_response[count];
     * buffer needs to be freed by caller
     */
    return listen_buf;

errout:
    free (listen_buf);
    return NULL;
}
