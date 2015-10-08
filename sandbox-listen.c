/*****************************************************************
 * Copyright 2015 Rackspace, Inc.
 *
 * listen on a unix domain socket for incoming patches
 ****************************************************************/
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "sandbox.h"


#define QLEN 5 // depth of the listening queue
#define STALE 30 // timout for client user id data

// WRS


// create and listen on a unix domain socket.
// connect, peek at the incoming data. 
// sock_name: full path of the socket e.g. /var/run/sandbox 
int listen_sandbox_sock(const char *sock_name)
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
