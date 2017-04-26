#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"


void *
_zalloc (size_t size)
{
  void *buf = malloc (size);
  if (!buf)
    {
      fprintf (stderr, "Failed to allocate %Zu bytes of memory\n", size);
      exit (1);
    }

  memset (buf, 0, size);

  return buf;
}


void *
_realloc (void *buf, size_t size)
{
  void *newbuf = realloc (buf, size);
  if (!newbuf)
    {
      fprintf (stderr, "Failed to reallocate %Zu bytes of memory\n", size);
      exit (1);
    }

  return newbuf;
}


#define MAJORFILE	"/sys/hypervisor/version/major"
#define MINORFILE	"/sys/hypervisor/version/minor"
#define EXTRAFILE	"/sys/hypervisor/version/extra"
#define COMPILEDATEFILE	"/sys/hypervisor/compilation/compile_date"


int
_read_line (char *filename, char *buf, size_t bufsize)
{
  FILE *f = fopen (filename, "r");
  if (!f)
    {
      fprintf (stderr, "error: fopen(%s): %m\n", filename);
      return -1;
    }

  int failed = (fgets (buf, bufsize, f) == NULL);
  fclose (f);
  if (failed)
    {
      fprintf (stderr, "error: fgets(%s): %m\n", filename);
      return -1;
    }

  /* Strip off trailing \n */
  size_t len = strlen (buf);
  if (buf[len - 1] == '\n')
    {
      buf[len - 1] = 0;
      len--;
    }

  return len;
}


int
get_xen_version (char *buf, size_t bufsize)
{
  char major[64], minor[64], extra[64];

  if (_read_line (MAJORFILE, major, sizeof (major)) < 0)
    return -1;
  if (_read_line (MINORFILE, minor, sizeof (minor)) < 0)
    return -1;
  if (_read_line (EXTRAFILE, extra, sizeof (extra)) < 0)
    return -1;

  return snprintf (buf, bufsize, "%s.%s%s", major, minor, extra);
}


int
get_xen_compile_date (char *buf, size_t bufsize)
{
  return _read_line (COMPILEDATEFILE, buf, bufsize);
}

int
string2sha1 (const unsigned char *string, unsigned char *sha1)
{
  int i, ccode;
  /* Make sure first 40 chars of string are composed of only hex digits */
  for (i = 0; i < 40; i += 2)
    {
      if ((ccode =
	   sscanf ((const char *) string + i, "%02x",
		   (int *) (&sha1[i / 2]))) != 1)
	{
	  fprintf (stderr, "error: not a valid sha1 string: %s\n", string);
	  return -1;
	}
    }
  return 0;
}
