#ifndef XEN_LIVEPATCH_PATCH_FILE_H_H
#define XEN_LIVEPATCH_PATCH_FILE_H_H

#define STR1(s) #s
#define STR(s)  STR1(s)

#define XSPATCH_VER2    2
#define XSPATCH_VER3    3
#define _XSPATCH_COOKIE "XSPATCH"

#define XSPATCH_COOKIE_LEN  8

#define XSPATCH_COOKIE	_XSPATCH_COOKIE STR(XSPATCH_VER2)
#define XSPATCH_COOKIE3	_XSPATCH_COOKIE STR(XSPATCH_VER3)


struct check {
    uint64_t hvabs;
    uint16_t datalen;
    unsigned char *data;
};


struct function_patch {
    char *funcname;
    uint64_t oldabs;
    uint32_t newrel;
};


struct table_patch {
    char *tablename;
    uint64_t hvabs;
    uint16_t datalen;
    unsigned char *data;
};


struct patch {
    unsigned char sha1[SHA_DIGEST_LENGTH];

    char xenversion[32];
    char xencompiledate[32];

    uint64_t crowbarabs;
    uint64_t refabs;

    uint32_t bloblen;
    unsigned char *blob;

    uint16_t numrelocs;
    uint32_t *relocs;

    uint16_t numchecks;
    struct check *checks;

    uint16_t numfuncs;
    struct function_patch *funcs;

    uint16_t numtables;
    struct table_patch *tables;
};

/* V3 patch data structures */
struct reloc3 {
    uint16_t index;
    uint32_t offset;
};

struct symbol {
    char *name;
    char *section;
    uint32_t sec_off;
    uint32_t sym_off;
};

struct dependency {
    unsigned char sha1[SHA_DIGEST_LENGTH];
    uint64_t refabs;
    uint32_t reladdr;
};

struct patch3 {
    union {
        struct patch;
        struct patch v2;
    };
    int version;
    char * tags;
    uint16_t numrelocs3;
    struct reloc3 *relocs3;
    uint16_t numsymbols;
    struct symbol *symbols;
    uint16_t numdeps;
    struct dependency *deps;
};

int _read(int fd, const char *filename, void *buf, size_t buflen);
int _readu64(int fd, const char *filename, uint64_t *value);
int _readu32(int fd, const char *filename, uint32_t *value);
int _readu16(int fd, const char *filename, uint16_t *value);

int load_patch_file3(int fd, const char *filename, struct patch3 *patch);
int load_patch_file(int fd, const char *filename, struct patch *patch);

void print_patch_file_info(struct patch3 *patch);
void print_json_patch_info(struct patch3 *patch);

#endif //XEN_LIVEPATCH_PATCH_FILE_H_H
