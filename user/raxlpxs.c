#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h>
#include <limits.h>
#include <sys/fcntl.h>

#include <zlib.h>

#include <libelf.h>

#include <openssl/sha.h>

#include "util.h"
#include "patch_file.h"
#include "../sandbox.h"
#include "portability.h"

/* stuff from private xen headers */

#ifndef sandbox_port
#ifdef HYPERCALL_BUFFER_AS_ARG
#define DECLARE_NAMED_HYPERCALL_BOUNCE(_name, _ubuf, _sz, _dir) \
    xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(_name) = {  \
        .hbuf = NULL,                                           \
        .param_shadow = NULL,                                   \
        .sz = _sz, .dir = _dir, .ubuf = _ubuf,                  \
    }


#define DECLARE_HYPERCALL_BOUNCE(_ubuf, _sz, _dir) DECLARE_NAMED_HYPERCALL_BOUNCE(_ubuf, _ubuf, _sz, _dir)


#define XC_HYPERCALL_BUFFER_BOUNCE_NONE	0
#define XC_HYPERCALL_BUFFER_BOUNCE_IN	1
#define XC_HYPERCALL_BUFFER_BOUNCE_OUT	2
#define XC_HYPERCALL_BUFFER_BOUNCE_BOTH	3


int xc__hypercall_bounce_pre(xc_interface *xch, xc_hypercall_buffer_t *bounce);
void xc__hypercall_bounce_post(xc_interface *xch, xc_hypercall_buffer_t *bounce);

#define xc_hypercall_bounce_pre(_xch, _name) xc__hypercall_bounce_pre(_xch, HYPERCALL_BUFFER(_name))
#define xc_hypercall_bounce_post(_xch, _name) xc__hypercall_bounce_post(_xch, HYPERCALL_BUFFER(_name))
#else
#define HYPERCALL_BUFFER_AS_ARG(d)	((unsigned long)d)
#define xc_hypercall_bounce_pre(_xch, _name)
#define xc_hypercall_bounce_post(_xch, _name)
#endif

#endif/* #ifndef  sandbox_port */


typedef struct privcmd_hypercall {
    uint64_t op;
    uint64_t arg[5];
} privcmd_hypercall_t;

#define DECLARE_HYPERCALL privcmd_hypercall_t hypercall

#ifdef XENCTRL_HAS_XC_INTERFACE
typedef xc_interface* xc_interface_t;
#else
typedef int xc_interface_t;
#endif
static int json = 0;


#ifndef sandbox_port
int do_xen_hypercall(xc_interface_t xch, privcmd_hypercall_t *hypercall);


/* if this is a portable build for the sandbox, this function
 * is defined in portability.o
 */

int open_xc(xc_interface_t *xch)
{
#ifdef XENCTRL_HAS_XC_INTERFACE
    *xch = xc_interface_open(NULL, NULL, 0);
#else
    *xch = xc_interface_open();
#endif
    if (!*xch) {
        printf("xc_interface_open failed\n");
        return -1;
    }

    return 0;
}
#endif /*! sandbox_port */

#ifndef sandbox_port

int _do_lp_buf_op_both(xc_interface_t xch, void *buf, size_t buflen, uint64_t op)
{
#ifdef DECLARE_HYPERCALL_BOUNCE
    DECLARE_HYPERCALL_BOUNCE(buf, buflen,
                             XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    if (xc_hypercall_bounce_pre(xch, buf)) {
        perror("xc_hypercall_bounce_pre");
        return -ENOMEM;
    }

    void *dest = HYPERCALL_BUFFER(buf);

    DECLARE_HYPERCALL_BUFFER_ARGUMENT(dest);
#else
    void *dest = buf;
#endif

    DECLARE_HYPERCALL;

    hypercall.op = __HYPERVISOR_arch_2;	/* do_live_patch */
    hypercall.arg[0] = op;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(dest);

    int rc = do_xen_hypercall(xch, &hypercall);
    xc_hypercall_bounce_post(xch, buf);
    return rc;
}

#endif 
int do_lp_list(xc_interface_t xch, struct xenlp_list *list)
{
#ifndef sandbox_port
    return _do_lp_buf_op_both(xch, list, sizeof(*list), XENLP_list);
#else
    return __do_lp_list(xch, list);
#endif /* ! sandbox_port */
}


int do_lp_list3(xc_interface_t xch, struct xenlp_list3 *list){
#ifndef sandbox_port
    return _do_lp_buf_op_both(xch, list, sizeof(*list), XENLP_list3);
#else
    return __do_lp_list3(xch, list);;
#endif /* ! sandbox_port */
}


int do_lp_caps(xc_interface_t xch, struct xenlp_caps *caps)
{
#ifndef sandbox_port
    return _do_lp_buf_op_both(xch, caps, sizeof(*caps), XENLP_caps);
#else
    return __do_lp_caps(xch, caps);
#endif /* ! sandbox_port */
}


#ifndef sandbox_port
int _do_lp_buf_op(xc_interface_t xch, void *buf, size_t buflen, uint64_t op)
{
#ifdef DECLARE_HYPERCALL_BOUNCE
    DECLARE_HYPERCALL_BOUNCE(buf, buflen, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    if (xc_hypercall_bounce_pre(xch, buf)) {
        perror("xc_hypercall_bounce_pre");
        return -ENOMEM;
    }

    void *dest = HYPERCALL_BUFFER(buf);

    DECLARE_HYPERCALL_BUFFER_ARGUMENT(dest);
#else
    void *dest = buf;
#endif

    DECLARE_HYPERCALL;

    hypercall.op = __HYPERVISOR_arch_2;	/* do_live_patch */
    hypercall.arg[0] = op;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(dest);

    return do_xen_hypercall(xch, &hypercall);
}

#endif /* ! sandbox_port */
int do_lp_apply(xc_interface_t xch, void *buf, size_t buflen)
{
#ifndef sandbox_port
    return _do_lp_buf_op(xch, buf, buflen, XENLP_apply);
#else
    return __do_lp_apply(xch, buf, buflen);
#endif /* ! sandbox_port */
}


int do_lp_apply3(xc_interface_t xch, void *buf, size_t buflen)
{
#ifndef sandbox_port
    return _do_lp_buf_op(xch, buf, buflen, XENLP_apply3);
#else
    return __do_lp_apply3(xch, buf, buflen);
#endif /* ! sandbox_port */
    
}


int do_lp_undo3(xc_interface_t xch, void *buf, size_t buflen)
{
#ifndef sandbox_port
    return _do_lp_buf_op(xch, buf, buflen, XENLP_undo3);
#else
    return __do_lp_undo3(xch, buf, buflen);
#endif /* ! sandbox_port */
    
}

#ifndef sandbox_port
int usage(char *argv0)
{
    char *p = strrchr(argv0, '/');
    if (p)
        argv0 = p + 1;	/* Don't want to start at the / */

    fprintf(stderr, "usage: %s <command> [<args>]\n", argv0);
    fprintf(stderr, "\n");
    fprintf(stderr, "Available commands:\n");
    fprintf(stderr, "    list\t\tList all applied patches\n");
    fprintf(stderr, "    apply <filename>\tApply patch\n");
    fprintf(stderr, "    info <filename>\tDisplay information about patch\n");
    fprintf(stderr, "    undo <sha1>\tUn-apply a patch\n");
    fprintf(stderr, "    listj\t\tList all applied patches (json format)\n");
    fprintf(stderr, "    infoj <filename>\tDisplay information about patch "
                    "(json format)\n");

    return 1;
}

#else
void usage(void)
{
	printf("\nraxlpqemu --info --list --apply <patch> \
--remove <patch> --socket <sockname>  --debug --help\n");
	exit(0);	
}

#endif


#ifndef sandbox_port
int find_patch(xc_interface_t xch, unsigned char *sha1, size_t sha1_size,
               struct xenlp_patch_info **patch)
{
    /* Do a list first and make sure patch isn't already applied yet */
    struct xenlp_list list = { .skippatches = 0 };

    int ret = do_lp_list(xch, &list);
    if (ret < 0) {
        fprintf(stderr, "failed to get list: %m\n");
        return -1;
    }

    int totalpatches = 0;
    while (1) {
        int i;
        for (i = 0; i < list.numpatches; i++) {
            struct xenlp_patch_info *pi = &list.patches[i];

            /* int j; this is from the original file, appears to be extraneous */
            
            if (memcmp(pi->sha1, sha1, sha1_size) == 0) {
                *patch = pi;
                return 0;
            }

            totalpatches++;
        }

        if (list.numpatches < MAX_LIST_PATCHES)
            break;

        list.skippatches = totalpatches;

        ret = do_lp_list(xch, &list);
        if (ret < 0) {
            fprintf(stderr, "failed to get list: %m\n");
            return -1;
        }
    }
    return 0;
}

#endif

int find_patch3(xc_interface_t xch, unsigned char *sha1, size_t sha1_size,
               struct xenlp_patch_info3 **patch)
{
    /* Do a list first and make sure patch isn't already applied yet */
    struct xenlp_list3 list = { .skippatches = 0 };

    int ret = do_lp_list3(xch, &list);
    if (ret < 0) {
        fprintf(stderr, "failed to get list: %m\n");
        return -1;
    }

    int totalpatches = 0;
    while (1) {
        int i;
        for (i = 0; i < list.numpatches; i++) {
            struct xenlp_patch_info3 *pi = &list.patches[i];
            /* int j; this is from the original file, appears to be extraneous */

            if (memcmp(pi->sha1, sha1, sha1_size) == 0) {
                *patch = pi;
                return 0;
            }

            totalpatches++;
        }

        if (list.numpatches < MAX_LIST_PATCHES)
            break;

        list.skippatches = totalpatches;

        ret = do_lp_list3(xch, &list);
        if (ret < 0) {
            fprintf(stderr, "failed to get list: %m\n");
            return -1;
        }
    }
    return 0;
}


#define ADR(d, s)	do { memcpy(ptr, d, s); ptr += s; } while (0)
#define AD(d)		ADR(&d, sizeof(d))
#define ADA(d, n)	ADR(d, sizeof(d[0]) * n)

size_t fill_patch_buf(unsigned char *buf, struct patch3 *patch,
                      uint32_t numwrites, struct xenlp_patch_write *writes)
{
    unsigned char *ptr = buf;
    struct xenlp_apply apply = {
        bloblen: patch->bloblen,

        numrelocs: patch->numrelocs,
        numwrites: numwrites,

        refabs: patch->refabs,
    };

    size_t buflen = sizeof(apply) + patch->bloblen +
                    (patch->numrelocs * sizeof(patch->relocs[0])) +
                    (numwrites * sizeof(writes[0]));

    if (buf == NULL)
        return buflen;

    memcpy(apply.sha1, patch->sha1, sizeof(apply.sha1));

    AD(apply);					/* struct xenlp_apply */
    if (patch->bloblen > 0)
        ADR(patch->blob, patch->bloblen);	/* blob */
    if (patch->numrelocs > 0)
        ADA(patch->relocs, patch->numrelocs);	/* relocs */
    if (numwrites > 0)
        ADA(writes, numwrites);			/* writes */

    return (ptr - buf);
}


size_t fill_patch_buf3(unsigned char *buf, struct patch3 *patch,
                      uint32_t numwrites, struct xenlp_patch_write *writes)
{
    size_t i;
    unsigned char *ptr = buf;
    struct xenlp_apply3 apply = {
            bloblen: patch->bloblen,

            numrelocs: patch->numrelocs,
            numwrites: numwrites,

            refabs: patch->refabs,
            numdeps: patch->numdeps,
            taglen: strnlen(patch->tags, MAX_TAGS_LEN - 1)
    };

    size_t buflen = sizeof(apply) + patch->bloblen +
                    (patch->numrelocs * sizeof(patch->relocs[0])) +
                    (numwrites * sizeof(writes[0])) +
                    (patch->numdeps * sizeof(patch->deps[0])) +
                    apply.taglen;

    if (buf == NULL)
        return buflen;

    memcpy(apply.sha1, patch->sha1, sizeof(apply.sha1));

    AD(apply);					/* struct xenlp_apply */
    if (patch->bloblen > 0)
        ADR(patch->blob, patch->bloblen);	/* blob */
    if (patch->numrelocs > 0)
        ADA(patch->relocs, patch->numrelocs);	/* relocs */
    if (numwrites > 0)
        ADA(writes, numwrites);			/* writes */
    if (apply.numdeps > 0) {
        struct xenlp_hash *deps = _zalloc(sizeof(struct xenlp_hash) *
                                          apply.numdeps);
        for (i = 0; i < apply.numdeps; i++)
            memcpy(deps[i].sha1, patch->deps[i].sha1,
                   sizeof(patch->deps[i].sha1));
        ADA(deps, apply.numdeps);    	/* deps */
        free(deps);
    }
    if (apply.taglen > 0)
        ADR(patch->tags, apply.taglen);
    return (ptr - buf);
}


void patch_writes(struct patch *patch, struct xenlp_patch_write *writes)
{
    size_t i;
    for (i = 0; i < patch->numfuncs; i++) {
        struct function_patch *func = &patch->funcs[i];
        struct xenlp_patch_write *pw = &writes[i];

        pw->hvabs = func->oldabs;

        /* Create jmp trampoline */
        /* jmps are relative to next instruction, so subtract out 5 bytes
         * for the jmp instruction itself */
        int32_t jmpoffset = (patch->refabs + func->newrel) - func->oldabs - 5;

        pw->data[0] = 0xe9;		/* jmp instruction */
        memcpy(&pw->data[1], &jmpoffset, sizeof(jmpoffset));

        pw->reloctype = XENLP_RELOC_INT32;
        pw->dataoff = 1;

        printf("Patching function %s @ %llx\n", func->funcname,
               (long long unsigned int)func->oldabs);
    }
}


int _cmd_apply2(xc_interface_t xch, struct patch3 *patch)
{
    size_t i;
    struct xenlp_patch_info *info = NULL;
    /* Do a list first and make sure patch isn't already applied yet */
    if (find_patch(xch, patch->sha1, sizeof(patch->sha1), &info) < 0) {
        fprintf(stderr, "error: could not search for patches\n");
        return -1;
    }
    if (info) {
        printf("Patch already applied, skipping\n");
        return 0;
    }
    /* Search for dependent patches, calculate relative address for each */
    for (i = 0; i < patch->numdeps; i++) {
        struct xenlp_patch_info *dep_patch = NULL;
        if (find_patch(xch, patch->deps[i].sha1, sizeof(patch->deps[i].sha1),
                       &dep_patch) < 0) {
            fprintf(stderr, "error: could not search for patches\n");
            return -1;
        }
        if (dep_patch == NULL) {
            char sha1str[SHA_DIGEST_LENGTH * 2 + 1];
            bin2hex(patch->deps[i].sha1, sizeof(patch->deps[i].sha1),
                    sha1str, sizeof(sha1str));
            fprintf(stderr, "error: dependency was not found in memory: "
                    "patch %s\n", sha1str);
            return -1;
        }
        /* Update the relative address */
        patch->deps[i].reladdr = (uint32_t )(dep_patch->hvaddr - patch->deps[i].refabs);
    }

    for (i = 0; i < patch->numrelocs3; i++) {
        struct reloc3 *rel3 = &patch->relocs3[i];
        if (rel3->index >= patch->numdeps) {
            fprintf(stderr, "error: invalid second level relocation "
                            "at %d: %d\n", rel3->index, rel3->offset);
            return -1;
        }
        /* Patch blob-related relocation here, we already know the
         * relative address */
        *((int32_t *) (patch->blob + rel3->offset)) += patch->deps[rel3->index].reladdr;
        printf("Patching dependent relocation to +%x @ %x\n",
               patch->deps[rel3->index].reladdr, rel3->offset);
        patch->relocs[patch->numrelocs + i] = rel3->offset;
    }
    patch->numrelocs += patch->numrelocs3;

    /* Convert into a series of writes for the live patch functionality */
    uint32_t numwrites = patch->numfuncs;
    struct xenlp_patch_write writes[numwrites];
    memset(writes, 0, sizeof(writes));
    patch_writes(&patch->v2, writes);

    size_t buflen = fill_patch_buf(NULL, patch, numwrites, writes);
    unsigned char *buf = _zalloc(buflen);
    buflen = fill_patch_buf(buf, patch, numwrites, writes);

    int ret = do_lp_apply(xch, buf, buflen);
    if (ret < 0) {
        fprintf(stderr, "failed to patch hypervisor: %m\n");
        return -1;
    }
    return 0;
}


int _cmd_apply3(xc_interface_t xch, struct patch3 *patch)
{
    size_t i;
    struct xenlp_patch_info3 *info = NULL;
    /* Do a list first and make sure patch isn't already applied yet */
    if (find_patch3(xch, patch->sha1, sizeof(patch->sha1), &info) < 0) {
        fprintf(stderr, "error: could not search for patches\n");
        return -1;
    }
    if (info) {
        printf("Patch already applied, skipping\n");
        return 0;
    }
    /* Search for dependent patches, calculate relative address for each */
    for (i = 0; i < patch->numdeps; i++) {
        struct xenlp_patch_info3 *dep_patch = NULL;
        if (find_patch3(xch, patch->deps[i].sha1, sizeof(patch->deps[i].sha1),
                        &dep_patch) < 0) {
            fprintf(stderr, "error: could not search for patches\n");
            return -1;
        }
        if (dep_patch == NULL) {
            char sha1str[SHA_DIGEST_LENGTH * 2 + 1];
            bin2hex(patch->deps[i].sha1, sizeof(patch->deps[i].sha1),
                    sha1str, sizeof(sha1str));
            fprintf(stderr, "error: dependency was not found in memory: "
                    "patch %s\n", sha1str);
            return -1;
        }
        /* Update the relative address */
        patch->deps[i].reladdr = (uint32_t )(dep_patch->hvaddr - patch->deps[i].refabs);
    }

    for (i = 0; i < patch->numrelocs3; i++) {
        struct reloc3 *rel3 = &patch->relocs3[i];
        if (rel3->index >= patch->numdeps) {
            fprintf(stderr, "error: invalid second level relocation "
                    "at %d: %d\n", rel3->index, rel3->offset);
            return -1;
        }
        /* Patch blob-related relocation here, we already know the
         * relative address */
        *((int32_t *) (patch->blob + rel3->offset)) += patch->deps[rel3->index].reladdr;
        printf("Patching dependent relocation to +%x @ %x\n",
               patch->deps[rel3->index].reladdr, rel3->offset);
        patch->relocs[patch->numrelocs + i] = rel3->offset;
    }
    patch->numrelocs += patch->numrelocs3;

    /* Convert into a series of writes for the live patch functionality */
    uint32_t numwrites = patch->numfuncs;
    struct xenlp_patch_write writes[numwrites];
    memset(writes, 0, sizeof(writes));
    patch_writes(&patch->v2, writes);

    size_t buflen = fill_patch_buf3(NULL, patch, numwrites, writes);
    unsigned char *buf = _zalloc(buflen);
    buflen = fill_patch_buf3(buf, patch, numwrites, writes);

    int ret = do_lp_apply3(xch, buf, buflen);
    if (ret < 0) {
        fprintf(stderr, "failed to patch hypervisor: %m\n");
        return -1;
    }
    return 0;
}

#ifndef sandbox_port
int cmd_apply(int argc, char *argv[])
#else
    int cmd_apply(int sockfd, char *path)
#endif
{

    char filepath[PATH_MAX];
#ifndef sandbox_port
    /*size_t i; apparently unused in original file */
    if (argc < 3)
        return usage(argv[0]);

    xc_interface_t xch;
    if (open_xc(&xch) < 0)
        return -1;

    const char *path = argv[2];
    
#else
    int xch = sockfd;
#endif
    /* basename() can modify its argument, so make a copy */
    strncpy(filepath, path, sizeof(filepath) - 1);
    filepath[sizeof(filepath) - 1] = 0;
    const char *filename = basename(filepath);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error: open(%s): %m\n", filepath);
        return -1;
    }

    struct patch3 patch;
/* TODO: should be able to load the patch using a full path, 
 * not just the basename
*/
    if (load_patch_file3(fd, filename, &patch) < 0)
        return -1;
    close(fd);
    
#ifndef sandbox_port
    /* make the xen/sandbox version check conditional */
    /* Make sure this patch applies to this version of Xen */
    char rxenversion[255];
    char rxencompiledate[255];

    if (get_xen_version(rxenversion, sizeof(rxenversion)) < 0)
        return -1;
    if (get_xen_compile_date(rxencompiledate, sizeof(rxencompiledate)) < 0)
        return -1;

    printf("Running Xen Information:\n");
    printf("  Hypervisor Version: %s\n", rxenversion);
    printf("  Hypervisor Compile Date: %s\n", rxencompiledate);

    printf("\n");
    printf("Patch (v%d) Applies To:\n", patch.version);
    printf("  Hypervisor Version: %s\n", patch.xenversion);
    printf("  Hypervisor Compile Date: %s\n", patch.xencompiledate);
    printf("\n");

    if (strcmp(rxenversion, patch.xenversion) != 0 ||
        strcmp(rxencompiledate, patch.xencompiledate) != 0) {
        fprintf(stderr, "error: patch does not match hypervisor build\n");
        return -1;
    }

#else
/* check for QEMU version and sandbox build info */
    LMSG("Getting QEMU/sandbox info\n");
    
    char *qemu_version = get_qemu_version(xch);
    char *qemu_compile_date = get_qemu_date(xch);
    if (!strlen(qemu_version) || !strlen(qemu_compile_date)) {
	    LMSG("error getting version and complilation data\n");
	    return SANDBOX_ERR_RW;	    
    }

 
    LMSG("  QEMU Version: %s\n", qemu_version);
    LMSG("  QEMU Compile Date: %s\n", qemu_compile_date);

    LMSG("\n");
    LMSG("Patch Applies To:\n");
    LMSG("  QEMU Version: %s\n", patch.xenversion);
    LMSG("  QEMU  Compile Date: %s\n", patch.xencompiledate);
    LMSG("\n");


    if (strncmp(qemu_version, patch.xenversion, INFO_STRING_LEN) != 0 ||
	strncmp(qemu_compile_date, patch.xencompiledate, INFO_STRING_LEN) != 0) {
	    LMSG("error: patch does not match QEMU build\n");
	    return SANDBOX_ERR_BAD_VER;
    }
    
#endif /* sandbox_port */
    
    /* Perform some sanity checks */
    if (patch.crowbarabs != 0) {
        fprintf(stderr, "error: cannot handle crowbar style patches\n");
        return -1;
    }

    if (patch.numchecks > 0) {
        fprintf(stderr, "error: cannot handle prechecks\n");
        return -1;
    }

    /* FIXME: Handle hypercall table writes too */
    if (patch.numtables > 0) {
        fprintf(stderr, "error: cannot handle table writes, yet\n");
        return -1;
    }

    struct xenlp_caps caps = { .flags = 0 };
    do_lp_caps(xch, &caps);
    if (caps.flags & XENLP_CAPS_V3) {
        if (_cmd_apply3(xch, &patch) < 0)
            return -1;
    } else {
#ifdef sandbox_port
        DMSG("error: using v2 livepatch ABI\n");
        return -1;
#else
        fprintf(stderr, "warn: using v2 livepatch ABI\n");
        if (_cmd_apply2(xch, &patch) < 0)
            return -1;
#endif
    }

    char sha1str[SHA_DIGEST_LENGTH * 2 + 1];
    bin2hex(patch.sha1, sizeof(patch.sha1), sha1str, sizeof(sha1str));
    printf("\nSuccessfully applied patch %s\n", sha1str);
    return 0;
}


static void print_list_header()
{
    if (json)
        printf("[");
    else {
        printf("Applied patches\n");
        printf("===============\n");
    }
}


static void print_list_footer()
{
    if (json)
        printf("]\n");
}



int _cmd_list2(xc_interface_t xch)
{
    struct xenlp_list list = { .skippatches = 0 };

    int ret = do_lp_list(xch, &list);
    if (ret < 0) {
        fprintf(stderr, "failed to get list: %m\n");
        return -1;
    }

    print_list_header();
    int last = 0;
    int totalpatches = 0;
    while (1) {
        int i;
        for (i = 0; i < list.numpatches; i++) {

#ifdef sandbox_port
            struct xenlp_patch_info3 *pi = &list.patches[i];
#else
            struct xenlp_patch_info *pi = &list.patches[i];
#endif
            int j;
            if (list.numpatches < MAX_LIST_PATCHES && i == list.numpatches - 1)
                last = 1;

            if (json)
                printf("\n  {\"sha1\": \"");

            for (j = 0; j < sizeof(pi->sha1); j++)
                printf("%02x", pi->sha1[j]);

            if (json)
                printf("\", \"hvaddr\": \"0x%llx\"}%s",
                       (long long unsigned)pi->hvaddr, ((last) ? "\n" : ","));
            else
                printf(" @ %llx\n", (long long unsigned)pi->hvaddr);

            totalpatches++;
        }

        if (list.numpatches < MAX_LIST_PATCHES)
            break;

        list.skippatches = totalpatches;

        ret = do_lp_list(xch, &list);
        if (ret < 0) {
            fprintf(stderr, "failed to get list: %m\n");
            return -1;
        }
    }
    print_list_footer();
    return 0;
}


void print_patch_info3(struct xenlp_patch_info3 *pi, int last)
{
    unsigned char sha1zero[SHA_DIGEST_LENGTH] = { 0 };
    int j;

    if (json)
        printf("\n  {\"sha1\": \"");

    for (j = 0; j < sizeof(pi->sha1); j++)
        printf("%02x", pi->sha1[j]);

    if (json) {
        printf("\",");
        printf(" \"tags\": \"%s\",", pi->tags);
    } else
        printf(" [%s]", pi->tags);

    for (j = 0; j < MAX_LIST_DEPS; j++) {
        if (memcmp(pi->deps[j].sha1, sha1zero, SHA_DIGEST_LENGTH) == 0)
            break;
        char hex[SHA_DIGEST_LENGTH * 2 + 1];
        bin2hex(pi->deps[j].sha1, SHA_DIGEST_LENGTH, hex, sizeof(hex));
        if (json) {
            printf(" \"dep\": \"%s\",", hex);
        } else
            printf(" dep: %s", hex);
    }
    if (json)
        printf(" \"hvaddr\": \"0x%llx\"}%s",
               (long long unsigned)pi->hvaddr, ((last) ? "\n" : ","));
    else
        printf(" @ %llx\n", (long long unsigned)pi->hvaddr);
}


int _cmd_list3(xc_interface_t xch)
{
    struct xenlp_list3 list = { .skippatches = 0 };

    int ret = do_lp_list3(xch, &list);
    if (ret < 0) {
        fprintf(stderr, "failed to get list: %m\n");
        return -1;
    }

    print_list_header();
    int totalpatches = 0;
    int last = 0;
    while (1) {
        int i;
        for (i = 0; i < list.numpatches; i++) {
            struct xenlp_patch_info3 *pi = &list.patches[i];
            if (list.numpatches < MAX_LIST_PATCHES && i == list.numpatches - 1)
                last = 1;
            print_patch_info3(pi, last);
            totalpatches++;
        }

        if (list.numpatches < MAX_LIST_PATCHES3)
            break;

        list.skippatches = totalpatches;

        ret = do_lp_list3(xch, &list);
        if (ret < 0) {
            fprintf(stderr, "failed to get list: %m\n");
            return -1;
        }
    }
    print_list_footer();
    return 0;
}

int cmd_list(int argc, char *argv[])
{
    xc_interface_t xch;
    if (open_xc(&xch) < 0)
        return -1;
    struct xenlp_caps caps = { .flags = 0 };
    do_lp_caps(xch, &caps);
    if (caps.flags & XENLP_CAPS_V3)
        return _cmd_list3(xch);
    else {
        fprintf(stderr, "warn: using v2 livepatch ABI\n");
        return _cmd_list2(xch);
    }
}


int info_patch_file(int fd, const char *filename)
{
    struct patch3 patch;
    /* size_t i; is apparently unused in the upstream file */
    if (load_patch_file3(fd, filename, &patch) < 0)
        return -1;
    close(fd);

    if (json)
        print_json_patch_info(&patch);
    else
        print_patch_file_info(&patch);
    return 0;
}


struct symbols {
    /* Offsets into .text section */
    size_t _offsets;

    size_t _token_table;
    size_t _token_table_size;

    size_t _names;
    size_t _names_size;

    size_t count;

    /* Parsed values */
    uint32_t *offsets;
    char *tokens[256];
    char **names;
};


int locate_symbols_offsets(Elf_Data *data, uint32_t start,
                           struct symbols *symbols)
{
    /* Find a long run of 32-bit values that look like valid offsets. The
     * values must be greater than or equal to the previous value and less
     * than the mapped size of the code from the ELF file */

    unsigned char *buf = data->d_buf;
    uint32_t end = start + data->d_size;
    size_t startoff = 0;
    uint32_t pvalue = 0;

    size_t off;
    for (off = 0; off < data->d_size; off += 4) {
        if (data->d_size - off < 4)
            break;

        uint32_t value = *(uint32_t *)(buf + off);
        if (start <= value && value < end && (!pvalue || value >= pvalue)) {
            if (!startoff)
                /* Potential start of array */
                startoff = off;

            pvalue = value;
        } else {
            if (startoff) {
                /* Potential end of array */
                uint32_t size = off - startoff;

                if (size > 1000 * 4) {
                    symbols->_offsets = startoff;
                    symbols->count = size / 4;
                    return 0;
                }

                startoff = 0;
                pvalue = 0;
            }
        }
    }

    return -1;
}


int locate_symbols_addresses(Elf_Data *data, struct symbols *symbols)
{
    /* Find a long run of 64-bit values that look like valid addresses. The
     * values must be greater than or equal to the previous value and less
     * than the mapped size of the code from the ELF file */

    uint64_t start = 0xffff000000000000ULL;
    unsigned char *buf = data->d_buf;
    size_t startoff = 0;
    uint32_t pvalue = 0;

    size_t off;
    for (off = 0; off < data->d_size; off += 8) {
        if (data->d_size - off < 8)
            break;

        uint64_t value = *(uint64_t *)(buf + off);
        if (start <= value && (!pvalue || value >= pvalue)) {
            if (!startoff)
                /* Potential start of array */
                startoff = off;

            pvalue = value;
        } else {
            if (startoff) {
                /* Potential end of array */
                uint32_t size = off - startoff;

                if (size > 1000 * 8) {
                    symbols->_offsets = startoff;
                    symbols->count = size / 8;
                    return 0;
                }

                startoff = 0;
                pvalue = 0;
            }
        }
    }

    return -1;
}


int extract_symbol_locations(Elf_Data *data, uint32_t start,
                             struct symbols *symbols)
{
    if (locate_symbols_offsets(data, start, symbols) == 0) {
        /* Found symbols_offsets */
        unsigned char *buf = data->d_buf + symbols->_offsets;
        symbols->offsets = _zalloc(symbols->count * sizeof(uint32_t));

        /* This assumes both the ELF file and host are same endian */
        memcpy(symbols->offsets, buf, symbols->count * sizeof(uint32_t));
    } else if (locate_symbols_addresses(data, symbols) == 0) {
        /* Found symbols_addresses */
        unsigned char *buf = data->d_buf + symbols->_offsets;
        symbols->offsets = _zalloc(symbols->count * sizeof(uint32_t));

        size_t i;
        uint64_t *p = (uint64_t *)buf;
        uint64_t absstart = 0;
        for (i = 0; i < symbols->count; i++, p++) {
            uint64_t value = *p;

            if (!absstart)
                absstart = value & ~0xFFFFFFULL;

            symbols->offsets[i] = value - absstart;
        }
    } else
        return -1;

    return 0;
}


int locate_symbols_token_table(Elf_Data *data, struct symbols *symbols)
{
    /* symbols_token_table is set of concatenated ASCIIZ strings. Look
     * for a long run of characters in the appropriate range. */

    char valid_chars[] = "_0123456789"
                         "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    unsigned char *buf = data->d_buf;
    size_t startoff = 0;
    size_t nullcount = 0;
    unsigned char pch = 0;
    size_t off;

    for (off = 0; off < data->d_size; off++) {
        unsigned char ch = *(buf + off);

        if ((ch == 0 || strchr(valid_chars, ch) != NULL) &&
                (ch != 0 || pch != 0)) {
            if (!startoff) {
                /* Potential start of array */
                startoff = off;
                nullcount = 0;
            }

            if (ch == 0)
                nullcount++;

            pch = ch;
        } else {
            if (startoff) {
                size_t size = off - startoff;

                /* Should be exactly 256 tokens */
                if (nullcount == 256) {
                    symbols->_token_table = startoff;
                    symbols->_token_table_size = size;

                    return 0;
                }

                startoff = 0;
                pch = 0;
            }
        }
    }

    return -1;
}


void extract_symbols_token_table(Elf_Data *data, struct symbols *symbols)
{
    char *buf = data->d_buf + symbols->_token_table;
    char *end = buf + symbols->_token_table_size;

    size_t i;
    for (i = 0; i < 256; i++) {
        symbols->tokens[i] = buf;

        char *p = memchr(buf, 0, end - buf);
        buf = p + 1;
    }
}


int locate_symbols_names(Elf_Data *data, struct symbols *symbols)
{
    /* Each symbol consists of a byte of how many tokens the symbol
     * consists of. Each symbol (length byte and array of tokens) is
     * then concatenated into a big blob to make symbols_names. */

    unsigned char *buf = data->d_buf;
    size_t i;
    for (i = 0; i < data->d_size; i++) {
        size_t off = i;
        size_t count = 0;
        unsigned char numtoks = buf[off];
        while (0 < numtoks && numtoks < 32) {
            if (count == 0) {
                /* First symbol should be '_stext'. This isn't as
                 * foolproof as I'd like it to be, but it's proved
                 * to be reliable for Xen 3.3 -> 4.4 at least. */
                size_t len = 0;
                size_t j;
                for (j = 0; j < numtoks; j++)
                    len += strlen(symbols->tokens[buf[off + 1 + j]]);

                char *name = _zalloc(len + 1);
                for (j = 0; j < numtoks; j++) {
                    char *token = symbols->tokens[buf[off + 1 + j]];
                    if (j == 0)
                        /* Skip leading 'T' or 't' in first token */
                        strcat(name, token + 1);
                    else
                        strcat(name, token);
                }

                int matched = (strcmp(name, "_stext") == 0);
                free(name);
                if (!matched)
                    break;
            }

            off += 1 + numtoks;
            if (off >= data->d_size)
                break;

            count++;
            numtoks = buf[off];
        }

        if (count >= symbols->count) {
            symbols->_names = i;
            symbols->_names_size = off - i;
            return 0;
        }
    }

    return -1;
}


void extract_symbols_names(Elf_Data *data, struct symbols *symbols)
{
    symbols->names = _zalloc(sizeof(symbols->names[0]) * symbols->count);

    unsigned char *buf = data->d_buf;
    size_t off = symbols->_names;
    /* size_t end = off + symbols->_names_size; is apparently unused in the upstream file */
    size_t i;
    for (i = 0; i < symbols->count; i++) {
        unsigned char numtoks = buf[off];

        /* Figure out the length of the concatenated tokens */
        size_t len = 0;
        size_t j;
        for (j = 0; j < numtoks; j++)
            len += strlen(symbols->tokens[buf[off + 1 + j]]);

        char *name = _zalloc(len + 1);
        for (j = 0; j < numtoks; j++) {
            char *token = symbols->tokens[buf[off + 1 + j]];
            if (j == 0)
                /* Skip leading 'T' or 't' in first token */
                strcat(name, token + 1);
            else
                strcat(name, token);
        }

        symbols->names[i] = name;

        off += 1 + numtoks;
    }
}


uint32_t get_symbol(struct symbols *symbols, char *name)
{
    size_t i;
    for (i = 0; i < symbols->count; i++) {
        if (strcmp(symbols->names[i], name) == 0)
            return symbols->offsets[i];
    }

    fprintf(stderr, "unable to find symbol %s\n", name);
    exit(1);
}


uint32_t _get_int_func_wrapper(Elf32_Shdr *text, Elf_Data *textdata,
                               struct symbols *symbols, char *name)
{
    uint32_t off = get_symbol(symbols, name);
    unsigned char *buf = textdata->d_buf + off - text->sh_addr;
    if (buf[0] != 0xb8) {
        fprintf(stderr, "could not extract int from %s\n", name);
        exit(1);
    }

    return *(uint32_t *)(buf + 1);
}


char *_get_string_func_wrapper(Elf32_Shdr *text, Elf_Data *textdata,
                               struct symbols *symbols, char *name)
{
    uint32_t off = get_symbol(symbols, name);
    unsigned char *buf = textdata->d_buf + off - text->sh_addr;
    if (memcmp(buf, "\x48\x8d\x05", 3) != 0) {
        fprintf(stderr, "could not extract string from %s\n", name);
        exit(1);
    }

    off += *(uint32_t *)(buf + 3);
    off += 7;	/* Offset is relative to next instruction */

    return textdata->d_buf + off - text->sh_addr;
}


int info_xen_gz(int origfd, const char *filename)
{
    /* dup the fd so we can call gzclose() since it closes the fd */
    int fd = dup(origfd);
    if (fd < 0) {
        fprintf(stderr, "error: dup(%d): %m\n", origfd);
        return -1;
    }

    gzFile file = gzdopen(fd, "r");
    if (!file) {
        fprintf(stderr, "error: gzdopen(%s): ", filename);
        goto err;
    }

    /* libelf works on either file descriptors (which we cannot use since
     * it's gzip compressed on disk) or a memory region. Thankfully xen.gz
     * is less than 2MB uncompressed, so loading it all into memory is
     * feasible for us. */
    size_t bytesalloced = 0, bytesread = 0;
    unsigned char *buf = NULL;
    while (1) {
        while (bytesread >= bytesalloced) {
            if (!bytesalloced)
                bytesalloced = 2 * 1024 * 1024;
            else
                bytesalloced *= 2;
            buf = _realloc(buf, bytesalloced);
        }

        int ret = gzread(file, buf + bytesread, bytesalloced - bytesread);
        if (ret < 0) {
            fprintf(stderr, "error: gzread(%s, %Zu): ", filename,
                    bytesalloced - bytesread);
            goto err;
        }
        if (ret == 0)
            break;

        bytesread += ret;
    }

    Elf *elf = elf_memory((char *)buf, bytesread);

    if (elf_kind(elf) != ELF_K_ELF) {
        fprintf(stderr, "%s: not an ELF file\n", filename);
        goto err2;
    }

    Elf32_Ehdr *ehdr = elf32_getehdr(elf);
    if (!ehdr) {
        fprintf(stderr, "%s: elf32_getehdr failed: ", filename);
        goto err;
    }

    Elf_Scn *strtab_scn = elf_getscn(elf, ehdr->e_shstrndx);
    if (!strtab_scn) {
        fprintf(stderr, "%s: unable to load .shstrtab section\n", filename);
        goto err2;
    }
    Elf_Data *strtab_data = elf_rawdata(strtab_scn, NULL);
    if (!strtab_data) {
        fprintf(stderr, "%s: unable to load .shstrtab data\n", filename);
        goto err2;
    }

    Elf32_Shdr *text = NULL;
    Elf_Data *textdata;

    int i;
    for (i = 0; i < ehdr->e_shnum; i++) {
        Elf_Scn *scn = elf_getscn(elf, i);
        Elf32_Shdr *shdr = elf32_getshdr(scn);
        char *name = strtab_data->d_buf + shdr->sh_name;
        if (strcmp(name, ".text") == 0) {
            text = shdr;
            textdata = elf_rawdata(scn, NULL);
        }
    }

    if (!text) {
        fprintf(stderr, "%s: could not find .text section\n", filename);
        goto err2;
    }

    struct symbols symbols;

    if (extract_symbol_locations(textdata, text->sh_addr, &symbols) < 0) {
        fprintf(stderr, "%s: could not find symbols_offsets "
                        "or symbols_addresses\n", filename);
        goto err2;
    }

    if (locate_symbols_token_table(textdata, &symbols) < 0) {
        fprintf(stderr, "%s: could not find symbols_token_table\n", filename);
        goto err2;
    }

    extract_symbols_token_table(textdata, &symbols);

    if (locate_symbols_names(textdata, &symbols) < 0) {
        fprintf(stderr, "%s: could not find symbols_names\n", filename);
        goto err2;
    }

    extract_symbols_names(textdata, &symbols);

    /* Now that we have a symbol table, start pulling out the data we want */

    uint32_t major_ver = _get_int_func_wrapper(text, textdata, &symbols,
                                               "xen_major_version");
    uint32_t minor_ver = _get_int_func_wrapper(text, textdata, &symbols,
                                               "xen_minor_version");
    char *extra_ver = _get_string_func_wrapper(text, textdata, &symbols,
                                               "xen_extra_version");
    printf("version: %d.%d%s\n", major_ver, minor_ver, extra_ver);

    char *compile_date = _get_string_func_wrapper(text, textdata, &symbols,
                                                  "xen_compile_date");
    printf("compile_date: %s\n", compile_date);

    char *changeset = _get_string_func_wrapper(text, textdata, &symbols,
                                               "xen_changeset");
    printf("changeset: %s\n", changeset);

    /* Calculate SHA1 hash of uncompressed data */
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, buf, bytesread);
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &sha1);

    char hex[SHA_DIGEST_LENGTH * 2 + 1];
    bin2hex(hash, sizeof(hash), hex, sizeof(hex));
    printf("sha1 hash: %s\n", hex);

    gzclose(file);
    return 0;

    /* C is weird, can't declare variables after label, so do it before */
    int errnum;
    const char *err;
err:
    err = gzerror(file, &errnum);
    if (errnum == Z_ERRNO)
        fprintf(stderr, "%m\n");
    else
        fprintf(stderr, "%s\n", err);

err2:
    gzclose(file);
    return -1;
}

#ifndef sandbox_port
int cmd_info(int argc, char *argv[])
{
    if (argc < 3)
        return usage(argv[0]);

    const char *path = argv[2];
    char filepath[PATH_MAX];

    /* basename() can modify its argument, so make a copy */
    strncpy(filepath, path, sizeof(filepath) - 1);
    filepath[sizeof(filepath) - 1] = 0;
    const char *filename = basename(filepath);

    /* Figure out if this is a patch file or xen.gz file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error: open(%s): %m\n", path);
        return -1;
    }

    unsigned char signature[XSPATCH_COOKIE_LEN];
    if (_read(fd, path, signature, sizeof(signature)) < 0)
        return -1;

    lseek(fd, 0, SEEK_SET);

    int ret = -1;
    if (memcmp(signature, XSPATCH_COOKIE, sizeof(signature)) == 0 ||
            memcmp(signature, XSPATCH_COOKIE3, sizeof(signature)) == 0)
        ret = info_patch_file(fd, filename);
    else if (signature[0] == 0x1f && signature[1] == 0x8b)
        ret = info_xen_gz(fd, filename);
    else
        fprintf(stderr, "%s: unknown file\n", filename);

    close(fd);

    return ret;
}
#endif

int _cmd_undo3(xc_interface_t xch, struct xenlp_hash *hash,
               const unsigned char *patch_hash)
{
    struct xenlp_patch_info3 *info = NULL;
    if (find_patch3(xch, hash->sha1, SHA_DIGEST_LENGTH, &info) < 0) {
        fprintf(stderr, "error: could not search for patches\n");
        return -1;
    }
    if (!info) {
        fprintf(stderr, "%s: patch not found in memory\n", patch_hash);
        return -1;
    }
    printf("Un-applying patch:\n  ");
    print_patch_info3(info, 1);

    size_t buflen = sizeof(struct xenlp_hash);
    unsigned char *buf = _zalloc(buflen);
    memcpy(buf, hash, buflen);

    int ret = do_lp_undo3(xch, buf, buflen);
    if (ret < 0) {
        if (errno == ENOENT) {
            fprintf(stderr, "failed to undo a hypervisor patch: "
                    "patch not found\n");
            return -1;
        } else if (errno == ENXIO) {
            fprintf(stderr, "failed to undo a hypervisor patch: "
                    "undo dependent patches first\n");
            return -1;
        } else {
            fprintf(stderr, "failed to undo a hypervisor patch: %m\n");
            return -1;
        }
    }
    return 0;
}

#ifndef sandbox_port
int cmd_undo(int argc, char *argv[])
#else
/* sha1 will be a string in the sandbox case */
int cmd_undo(unsigned char *sha1)
#endif
{
    
#ifndef sandbox_port    
    unsigned char sha1[SHA_DIGEST_LENGTH];
    if (argc < 3)
        return usage(argv[0]);
    const unsigned char *sha1hex = argv[2];
#else
    const unsigned char *sha1hex = sha1;    
#endif
    if (string2sha1(sha1hex, sha1) < 0)
        return -1;

    xc_interface_t xch;
    if (open_xc(&xch) < 0)
        return -1;

    struct xenlp_hash hash = {{0}};
    memcpy(hash.sha1, sha1, SHA_DIGEST_LENGTH);

    struct xenlp_caps caps = { .flags = 0 };
    do_lp_caps(xch, &caps);
    if (caps.flags & XENLP_CAPS_V3) {
        if (_cmd_undo3(xch, &hash, sha1hex) < 0)
            return -1;
    } else {
        fprintf(stderr, "error: no v3 ABI detected, undo disabled\n");
        return -1;
    }
#ifndef sandbox_port
    printf("\nSuccessfully un-applied patch %s\n", argv[2]);
#else
    LMSG("\n successfully un-applied patch %s\n", sha1hex);
    
#endif
    return 0;
}

#ifndef sandbox_port
int main(int argc, char *argv[])
{
    char *cmd;
    int ret;

    if (argc < 2)
        return usage(argv[0]);

    cmd = argv[1];
    if (strcmp(cmd, "listj") == 0) {
        json = 1;
        cmd = "list";
    } else if (strcmp(cmd, "infoj") == 0) {
        json = 1;
        cmd = "info";
    }

    char *argv0 = argv[0];
    char *p = strrchr(argv0, '/');
    if (p)
        argv0 = p + 1;	/* Don't want to start at the / */
    if (!json)
        printf("%s version 1.4 (built " __DATE__ " " __TIME__ ")\n\n", argv0);

    if (strcmp(cmd, "apply") == 0)
        ret = cmd_apply(argc, argv);
    else if (strcmp(cmd, "list") == 0)
        ret = cmd_list(argc, argv);
    else if (strcmp(cmd, "info") == 0)
        ret = cmd_info(argc, argv);
    else if (strcmp(cmd, "undo") == 0)
        ret = cmd_undo(argc, argv);
    else
        return usage(argv[0]);

    return ret == 0 ? 0 : 1;
}

#else
/***********************************************
 * with QEMU we need a more flexible way to pass args, 
 * we have at least a socket as an additional arg.
 * So, just use the cmdline from raxlpqemu 
 *********************************************/
static int info_flag, list_flag, find_flag, apply_flag, remove_flag, sock_flag;
static char filepath[PATH_MAX];
static char patch_basename[PATH_MAX];
static unsigned char patch_hash[SHA_DIGEST_LENGTH * 2 + 1];
char sockname[PATH_MAX];
extern int sockfd;


/* There is no defined order for options on the command line
 * so, we need to process all the options (except --help) before
 * running any of the commands. iow, don't run commands in the options 
 * switch, run them after done processing options.
 * 
 * Options can be short or long, for example --socket and -s are the same.
 * Options that require a parameter, for example socket name, must see 
 * the parameter before the next option appears on the command line.
 * e.g., --socket <sockname> or --apply <patchfile>
 */

static inline void get_options(int argc, char **argv)
{
    while (1) {
        if (argc < 2)
            usage();
		
        int c;
        static struct option long_options[] = {
            {"dummy-for-short-option", no_argument, NULL, 0},
            {"info", no_argument, &info_flag, 1},
            {"list", no_argument, &list_flag, 1},
            {"find", required_argument, &find_flag, 1},
            {"apply", required_argument, &apply_flag, 1},
            {"remove", required_argument, &remove_flag, 1},
            {"socket", required_argument, &sock_flag, 1},
            {"debug", no_argument, NULL, 0},
            {"help", no_argument, NULL, 0},
            {0,0,0,0}
        };
        int option_index = 0;
        c = getopt_long_only(argc, argv, "ila:u:s:dh",
                             long_options, &option_index);
        if (c == -1) {
            break;
        }
		
    restart_long:
        switch (option_index) {
        case 0:
            switch (c) {
            case  'i':
                option_index = 1;
                info_flag = 1;
                goto restart_long;
            case 'l':
                option_index = 2;
                list_flag = 1;
                goto restart_long;
            case 'f':
                option_index = 3;
                find_flag = 1;
                goto restart_long;
            case 'a':
                option_index = 4;
                apply_flag = 1;
                goto restart_long;
            case 'u':
                option_index = 5;
                remove_flag = 1;
                goto restart_long;
            case 's':
                option_index = 6;
                goto restart_long;
            case 'd':
                option_index = 7;
                goto restart_long;
            case 'h':
                option_index = 8;
                goto restart_long;
				
            default:
                break;
                usage();			
            }
            DMSG("selected option %s\n", long_options[option_index].name);
        case 1:
        {
                    
            info_flag = 1;
            DMSG("selected option %s\n", long_options[option_index].name);
        }break;
                    
        case 2: /* list */
            break;
        case 3: /* find */
        {
            strncpy((char *)patch_hash, optarg, SHA_DIGEST_LENGTH * 2 + 1);
            DMSG("find patch %s: %s\n", patch_hash);
            break;
        }
        case 4: /* apply */
        {
            strncpy(filepath, optarg, sizeof(filepath) - 1);
            /* TODO: clean up basename handling - detect errors */
            char *basep = basename(filepath);
            if (basep != NULL) {
                strncpy(patch_basename, basep, PATH_MAX);
            }
            DMSG("patch file: %s\n", patch_basename);
            break;
        }
        case 5: /* undo */
        {
            strncpy((char *)patch_hash, optarg, SHA_DIGEST_LENGTH * 2 + 1);
            DMSG("undo (remove)  patch %s: %s\n", patch_hash);
            break;
        }
        case 6: /* set socket */ 
        {                   
            strncpy(sockname, optarg, PATH_MAX);
            DMSG("socket: %s\n", sockname);
            break;
        }
        case 7:
        {
            set_debug(1);
            break;
                    
        }
        case 8:
        {
                    
            usage(); /* usage exits */
            break;
        }
                
        default:
                           
            break;
        
        }
    }        
}
                
int main(int argc, char **argv)            
{
	
    int ccode;
    get_options(argc, argv);

    if (sock_flag == 0 || (sockfd = connect_to_sandbox(sockname)) < 0) {
        DMSG("error connecting to sandbox server, did you specify the --socket? \n");
        return SANDBOX_ERR_RW;
    }
        
    /* we don't run these functions within the option switch because */
    /* we rely on having the sockname set, which can happen after other options */
    if (info_flag > 0) {
        /* info for xenlp inspects the patch file */
        /* this is a little different, it returns the QEMU build info strings */

        DMSG("calling get_info_strings with handle: %d\n", sockfd);
        
        int info = get_info_strings(sockfd, 1);
        if (info != SANDBOX_OK)  {	
            LMSG("error getting build info\n");
        }
    }

    if (list_flag > 0) {

        if ((ccode = _cmd_list3(sockfd)) < 0) {
            LMSG("error listing applied patches\n");
        }
    }

    
    if (find_flag) {
        struct xenlp_patch_info **patch_buf = NULL;
        unsigned char sha1[SHA_DIGEST_LENGTH + 2] = { 0 };
        
        string2sha1(patch_hash, sha1);

        ccode = find_patch(sockfd, sha1, SHA_DIGEST_LENGTH, patch_buf);
        if (ccode == 1) {
            DMSG("found patch: %s\n", patch_hash);
            /* TODO: print all patch info int txt, json */
        } else if (ccode == 0) {
            DMSG("Not found: %s\n", patch_hash);
        } else if (
            patch_buf < 0) {
            DMSG("error in find_patch: %d\n", ccode);
        }
        if (*patch_buf == NULL) {
            free(patch_buf);
        }
    }
    if (apply_flag > 0) {
        if ((ccode = cmd_apply(sockfd, filepath)) < 0) {
            DMSG("error applying patch %d\n", ccode);
        } else {
            LMSG("Patch %s successfully applied\n", filepath);
        }
    }
    if (remove_flag > 0) {
        /* getopt should have copied the sha1 hex string to patch_hash */
        /* cmd_undo */
        if ((ccode = cmd_undo(patch_hash)) < 0) {
            LMSG("Error reversing patch %s\n", patch_hash); 
        }
        
    }
        
    if (sockfd > 0)
        close(sockfd);
	
    LMSG("bye\n");
    return SANDBOX_OK;
	
}

#endif /* ! sandbox_port */
