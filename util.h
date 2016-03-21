#ifndef __UTIL_H__
#define __UTIL_H__

int _read(const char *filename, int fd, void *buf, size_t buflen);
int _readu64(const char *filename, int fd, uint64_t *value);
int _readu32(const char *filename, int fd, uint32_t *value);
int _readu16(const char *filename, int fd, uint16_t *value);
void *_zalloc(size_t size);
void *_realloc(void *buf, size_t size);
int get_xen_version(char *buf, size_t bufsize);
int get_xen_compile_date(char *buf, size_t bufsize);
#endif
