#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "util.h"


ssize_t	readn(int fd, void *vptr, size_t n);


int _read(const char *filename, int fd, void *buf, size_t buflen)
{
    int ret = readn(fd, buf, buflen);
    if (ret < 0) {
        fprintf(stderr, "%s: %m\n", filename);
        return -1;
    }
    if (ret < buflen) {
	    fprintf(stderr, "%s: expected %d bytes, read %d\n",
                filename, (int)buflen, ret);
        return -1;
    }

    return 0;
}


int _readu64(const char *filename, int fd, uint64_t *value)
{
    unsigned char buf[sizeof(uint64_t)];

    if (_read(filename, fd, buf, sizeof(buf)) < 0)
        return -1;

    *value = ((uint64_t)buf[0]) << 56 | ((uint64_t)buf[1]) << 48 |
             ((uint64_t)buf[2]) << 40 | ((uint64_t)buf[3]) << 32 |
             ((uint64_t)buf[4]) << 24 | ((uint64_t)buf[5]) << 16 |
             ((uint64_t)buf[6]) << 8 | ((uint64_t)buf[7]);
    return 0;
}


int _readu32(const char *filename, int fd, uint32_t *value)
{
    unsigned char buf[sizeof(uint32_t)];

    if (_read(filename, fd, buf, sizeof(buf)) < 0)
        return -1;

    *value = ((uint32_t)buf[0]) << 24 | ((uint32_t)buf[1]) << 16 |
             ((uint32_t)buf[2]) << 8 | ((uint32_t)buf[3]);
    return 0;
}


int _readu16(const char *filename, int fd, uint16_t *value)
{
    unsigned char buf[sizeof(uint16_t)];

    if (_read(filename, fd, buf, sizeof(buf)) < 0)
        return -1;

    *value = ((uint16_t)buf[0]) << 8 | ((uint16_t)buf[1]);
    return 0;
}


void *_zalloc(size_t size)
{
    void *buf = malloc(size);
    if (!buf) {
        fprintf(stderr, "Failed to allocate %Zu bytes of memory\n", size);
        exit(1);
    }

    memset(buf, 0, size);

    return buf;
}


void *_realloc(void *buf, size_t size)
{
    void *newbuf = realloc(buf, size);
    if (!newbuf) {
        fprintf(stderr, "Failed to reallocate %Zu bytes of memory\n", size);
        exit(1);
    }

    return newbuf;
}


#define MAJORFILE	"/sys/hypervisor/version/major"
#define MINORFILE	"/sys/hypervisor/version/minor"
#define EXTRAFILE	"/sys/hypervisor/version/extra"
#define COMPILEDATEFILE	"/sys/hypervisor/compilation/compile_date"


int _read_line(char *filename, char *buf, size_t bufsize)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "error: fopen(%s): %m\n", filename);
        return -1;
    }

    int failed = (fgets(buf, bufsize, f) == NULL);
    fclose(f);
    if (failed) {
        fprintf(stderr, "error: fgets(%s): %m\n", filename);
        return -1;
    }

    /* Strip off trailing \n */
    size_t len = strlen(buf);
    if (buf[len - 1] == '\n') {
        buf[len - 1] = 0;
        len--;
    }

    return len;
}


int get_xen_version(char *buf, size_t bufsize)
{
    char major[64], minor[64], extra[64];

    if (_read_line(MAJORFILE, major, sizeof(major)) < 0)
        return -1;
    if (_read_line(MINORFILE, minor, sizeof(minor)) < 0)
        return -1;
    if (_read_line(EXTRAFILE, extra, sizeof(extra)) < 0)
        return -1;

    return snprintf(buf, bufsize, "%s.%s%s", major, minor, extra);
}


int get_xen_compile_date(char *buf, size_t bufsize)
{
    return _read_line(COMPILEDATEFILE, buf, bufsize);
}
