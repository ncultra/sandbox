#include "sandbox.h"


int server_flag = 0, client_flag = 0;

int client_func (void *p)
{
	printf ("client %d\n", getpid ());

	char *spath = (char *) p;
	int s, len;
	struct sockaddr_un un, sun;
	char cpath[PATH_MAX];
	sprintf (cpath, "%d", getpid ());

	if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
		abort ();

	memset (&un, 0, sizeof (un));
	un.sun_family = AF_UNIX;
	sprintf (un.sun_path, cpath);

	len =
	    offsetof (struct sockaddr_un, sun_path) + strlen (un.sun_path);
	unlink (un.sun_path);
	if (bind (s, (struct sockaddr *) &un, len) < 0)
		abort ();

	if (chmod (un.sun_path, S_IRWXU) < 0)
		abort ();

	memset (&sun, 0, sizeof (sun));
	sun.sun_family = AF_UNIX;
	strncpy (sun.sun_path, spath, sizeof (sun.sun_path));
	len = offsetof (struct sockaddr_un, sun_path) + strlen (spath);
	printf ("client connecting to %s\n", spath);
	if (connect (s, (struct sockaddr *) &sun, len) < 0) {
		unlink (un.sun_path);
		printf ("connect from %s failed\n", un.sun_path);
		perror (NULL);
		abort ();
	}
	printf ("connected\n");

	while (1) {
		putchar (getchar ());
	}
	return 0;
}


int server_func (void *p)
{
	printf ("server\n");

	int s, len;
	struct sockaddr_un un;
	char server_path[PATH_MAX];

	if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		abort ();
	}

	sprintf (server_path, "%d", getpid ());
	unlink (server_path);
	memset (&un, 0, sizeof (un));
	un.sun_family = AF_UNIX;
	strncpy (un.sun_path, server_path, sizeof (un.sun_path));
	len =
	    offsetof (struct sockaddr_un, sun_path) + strlen (server_path);
	if (bind (s, (struct sockaddr_un *) &un, len) < 0) {
		abort ();
	}

	if (listen (s, 5) < 0) {
		printf ("listen failed\n");
		perror (NULL);
		abort ();
	}

	printf ("server listening on %s\n", server_path);


	int client_fd;
	len = sizeof (un);
	uid_t client_id;
	char name[PATH_MAX];


	do {
		(client_fd = accept (s, (struct sockaddr *) &un, &len));
	} while (errno == EINTR || errno == EAGAIN);

	if (client_fd < 0) {
		printf ("accept failed\n");
		perror (NULL);
		abort ();
	}

	printf ("connected\n");

	struct stat statbuf;
	len -= offsetof (struct sockaddr_un, sun_path);
	memset (name, 0, sizeof (name));
	memcpy (name, un.sun_path, len);
	if (stat (name, &statbuf) < 0) {
		printf ("can't stat client address\n");
		perror (NULL);
		abort ();
	}

	return s;
}


int main (int argc, char **argv)
{
	int c;

	while ((c = getopt (argc, argv, "c:s")) != -1) {
		switch (c) {
		case 'c':
			return client_func (optarg);
		case 's':
			return server_func (NULL);
		default:
			printf ("bye\n");
			exit (0);
		}
	}
	printf ("bye\n");

	exit (1);
}
