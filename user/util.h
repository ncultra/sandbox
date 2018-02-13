#ifndef __UTIL_H__
#define __UTIL_H__

void *_zalloc (size_t size);
void *_realloc (void *buf, size_t size);
int get_xen_version (char *buf, size_t bufsize);
int get_xen_compile_date (char *buf, size_t bufsize);
void bin2hex (unsigned char *bin, size_t binlen, char *buf, size_t buflen);
int string2sha1 (const char *string, unsigned char *sha1);

#endif
