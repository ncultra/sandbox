/*
 * live_patch.h
 *
 * Each ABI is defined seperately. This allows a change in the userspace
 * to hypervisor ABI to be done without requiring a change to the ABI
 * between extract_patch and raxlpxs.
 *
 * Copyright 2015 Rackspace
 *
 */

#ifndef __XEN_PUBLIC_LIVE_PATCH_H__
#define __XEN_PUBLIC_LIVE_PATCH_H__


/* The ABI version must match `extract_patch` and `raxlpxs` */
#define MAX_LIST_PATCHES	64
#define MAX_PATCH_SIZE		1048576	/* FIXME: is 1MB too small? */
#define MAX_TAGS_LEN	    128
#define MAX_LIST_DEPS       8
#define MAX_LIST_PATCHES3	16


/* Any change to the userspace to hypervisor ABI should result in using a
 * new cmd id. Note any previously used ids below if deprecating (so they
 * don't get used again). */

/* cmd 0, old XENLP_info command without vaddr */
/* cmd 1, old XENLP_allocate_memory command */
/* cmd 2, old XENLP_apply_patch command without relocation */
#define XENLP_list		10
#define XENLP_apply		11

#define XENLP_caps      13
#define XENLP_list3     14
#define XENLP_apply3    15
#define XENLP_undo3     16

#define XENLP_CAPS_V3   0x1


/* Packing of the structures is different between 32-bit and 64-bit.
 * We want the packing to be the same so we have to install only one
 * function in the hypervisor. Unfortunately the "pack" #pragma only
 * specifices the maximum alignment, but we need a way to specify the
 * minimum alignment. As a result, we do the padding explicitly. */

/*
 *
 * XENLP_list (cmd 10)
 *
 */

struct xenlp_patch_info {
    uint64_t hvaddr;		/* virtual address in hypervisor memory */
    unsigned char sha1[20];	/* binary encoded */
    char __pad[4];
};


struct xenlp_list {
    uint16_t skippatches;	/* input, number of patches to skip */
    uint16_t numpatches;	/* output, number of patches returned */
    char __pad[4];
    struct xenlp_patch_info patches[MAX_LIST_PATCHES];	/* output */
};


/*
 *
 * XENLP_apply (cmd 11)
 *
 */
#define XENLP_RELOC_UINT64	0	/* function dispatch tables, etc */
#define XENLP_RELOC_INT32	1	/* jmp instructions, etc */

struct xenlp_patch_write {
    uint64_t hvabs;		/* Absolute address in HV to apply patch */

    unsigned char data[8];	/* 8-bytes of data to write at location */

    uint8_t reloctype;		/* XENLP_RELOC_ABS, XENLP_RELOC_REL */
    char dataoff;		/* Offset into data to apply relocation */

    char __pad[6];
};


/* layout in memory:
 *
 * struct xenlp_apply
 * blob (bloblen)
 * relocs (numrelocs * uint32_t)
 * writes (numwrites * struct xenlp_patch_write) */
struct xenlp_apply {
    unsigned char sha1[20];	/* SHA1 of patch file (binary) */

    char __pad0[4];

    uint32_t bloblen;		/* Length of blob */

    uint32_t numrelocs;		/* Number of relocations */

    uint32_t numwrites;		/* Number of writes */

    char __pad1[4];

    uint64_t refabs;		/* Reference address for relocations */
};

struct xenlp_hash {
    unsigned char sha1[20];

    char __pad0[4];
};

/* layout in memory:
 *
 * struct xenlp_apply
 * blob (bloblen)
 * relocs (numrelocs * uint32_t)
 * writes (numwrites * struct xenlp_patch_write)
 * deps (numdeps * struct xenlp_dep)
 * tags (taglen) */
struct xenlp_apply3 {
    unsigned char sha1[20];	/* SHA1 of patch file (binary) */

    char __pad0[4];

    uint32_t bloblen;		/* Length of blob */

    uint32_t numrelocs;		/* Number of relocations */

    uint32_t numwrites;		/* Number of writes */

    char __pad1[4];

    uint64_t refabs;		/* Reference address for relocations */

    uint32_t numdeps;       /* Number of dependendencies */

    uint32_t taglen;        /* length of tags string */
};

struct xenlp_patch_info3 {
    uint64_t hvaddr;		/* virtual address in hypervisor memory */
    unsigned char sha1[20];	/* binary encoded */
    char __pad[4];
    char tags[MAX_TAGS_LEN];
    struct xenlp_hash deps[MAX_LIST_DEPS];
};

struct xenlp_list3 {
    uint16_t skippatches;	/* input, number of patches to skip */
    uint16_t numpatches;	/* output, number of patches returned */
    char __pad[4];
    struct xenlp_patch_info3 patches[MAX_LIST_PATCHES3];	/* output */
};

struct xenlp_caps {
    uint64_t flags;
};

#endif /* __XEN_PUBLIC_LIVE_PATCH_H__ */
