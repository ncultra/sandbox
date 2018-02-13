/*
 * live_patch.h
 *
 * Each ABI is defined seperately. This allows a change in the userspace
 * to hypervisor ABI to be done without requiring a change to the ABI
 * between extract_patch and raxlpxs.
 *
 * Copyright 2015-2017 Rackspace
 */

#ifndef __XEN_PUBLIC_LIVE_PATCH_H__
#define __XEN_PUBLIC_LIVE_PATCH_H__


/* The ABI version must match `extract_patch` and `raxlpxs` */
#define MAX_PATCH_SIZE		1048576	/* FIXME: is 1MB too small? */

#define MAX_LIST_PATCHES2	64
#define MAX_TAGS_LEN		128
#define MAX_LIST_DEPS		8
#define MAX_LIST_PATCHES3	16


/* Any change to the userspace to hypervisor ABI should result in using a
 * new cmd id. Note any previously used ids below if deprecating (so they
 * don't get used again). */

/* lp1 (never deployed) */
/* cmd 0, old XENLP_info command without vaddr */
/* cmd 1, old XENLP_allocate_memory command */
/* cmd 2, old XENLP_apply_patch command without relocation */

/* lp2 */
#define XENLP_list2		10	/* first deployed version */
#define XENLP_apply2		11

/* lp3 */
#define XENLP_caps		13	/* query capabilities */
#define XENLP_list3		14	/* adds tags and deps */
#define XENLP_apply3		15	/* adds tags and deps */
#define XENLP_undo3		16	/* undo patch */

/* lp4 */
#define XENLP_apply4		17	/* adds ex_table */


/* Flags used for XENLP_caps */
#define XENLP_CAPS_V3		0x1	/* XENLP_{list3,apply3,undo3} */
#define XENLP_CAPS_APPLY4	0x2	/* XENLP_apply4 */


/* Packing of the structures is different between 32-bit and 64-bit.
 * We want the packing to be the same so we have to install only one
 * function in the hypervisor. Unfortunately the "pack" #pragma only
 * specifices the maximum alignment, but we need a way to specify the
 * minimum alignment. As a result, we do the padding explicitly. */

/* XENLP_caps */
struct xenlp_caps
{
  /* Bitmask of XENLP_CAPS_* */
  uint64_t flags;
};


struct xenlp_patch_info2
{
  uint64_t hvaddr;		/* virtual address in hypervisor memory */
  unsigned char sha1[20];	/* binary encoded */
  char __pad[4];
};

/* XENLP_list2 */
struct xenlp_list2
{
  uint16_t skippatches;		/* input, number of patches to skip */
  uint16_t numpatches;		/* output, number of patches returned */
  char __pad[4];
  struct xenlp_patch_info2 patches[MAX_LIST_PATCHES2];	/* output */
};


struct xenlp_hash
{
  unsigned char sha1[20];

  char __pad0[4];
};

struct xenlp_patch_info3
{
  uint64_t hvaddr;		/* virtual address in hypervisor memory */
  unsigned char sha1[20];	/* binary encoded */
  char __pad[4];
  char tags[MAX_TAGS_LEN];
  struct xenlp_hash deps[MAX_LIST_DEPS];
};

/* XENLP_list3 */
struct xenlp_list3
{
  uint16_t skippatches;		/* input, number of patches to skip */
  uint16_t numpatches;		/* output, number of patches returned */
  char __pad[4];
  struct xenlp_patch_info3 patches[MAX_LIST_PATCHES3];	/* output */
};


#define XENLP_RELOC_UINT64	0	/* function dispatch tables, etc */
#define XENLP_RELOC_INT32	1	/* jmp instructions, etc */

struct xenlp_patch_write
{
  uint64_t hvabs;		/* Absolute address in HV to apply patch */

  unsigned char data[8];	/* 8-bytes of data to write at location */

  uint8_t reloctype;		/* XENLP_RELOC_ABS, XENLP_RELOC_REL */
  char dataoff;			/* Offset into data to apply relocation */

  char __pad[6];
};

/* XENLP_apply2
 *
 * layout in memory:
 *
 * struct xenlp_apply2
 * blob (bloblen)
 * relocs (numrelocs * uint32_t)
 * writes (numwrites * struct xenlp_patch_write) */
struct xenlp_apply2
{
  unsigned char sha1[20];	/* SHA1 of patch file (binary) */

  char __pad0[4];

  uint32_t bloblen;		/* Length of blob */

  uint32_t numrelocs;		/* Number of relocations */

  uint32_t numwrites;		/* Number of writes */

  char __pad1[4];

  uint64_t refabs;		/* Reference address for relocations */
};


/* XENLP_apply3
 *
 * layout in memory:
 *
 * struct xenlp_apply3
 * blob (bloblen)
 * relocs (numrelocs * uint32_t)
 * writes (numwrites * struct xenlp_patch_write)
 * deps (numdeps * struct xenlp_dep)
 * tags (taglen) */
struct xenlp_apply3
{
  unsigned char sha1[20];	/* SHA1 of patch file (binary) */

  char __pad0[4];

  uint32_t bloblen;		/* Length of blob */

  uint32_t numrelocs;		/* Number of relocations */

  uint32_t numwrites;		/* Number of writes */

  char __pad1[4];

  uint64_t refabs;		/* Reference address for relocations */

  uint32_t numdeps;		/* Number of dependendencies */

  uint32_t taglen;		/* length of tags string */
};


struct xenlp_exctbl_entry
{
  /* Both fields are relative to start of blob */
  uint32_t addrrel;
  uint32_t contrel;
};

/* XENLP_apply4
 *
 * layout in memory:
 *
 * struct xenlp_apply4
 * blob (bloblen)
 * relocs (numrelocs * uint32_t)
 * writes (numwrites * struct xenlp_patch_write)
 * exctblents (numexctblents * struct xenlp_exctbl_entry)
 * preexctblents (numpreexctblents * struct xenlp_exctbl_entry)
 * deps (numdeps * struct xenlp_dep)
 * tags (taglen) */
struct xenlp_apply4
{
  unsigned char sha1[20];	/* SHA1 of patch file (binary) */

  char __pad0[4];

  uint64_t refabs;		/* Reference address for relocations */

  uint32_t bloblen;		/* Length of blob */

  uint32_t numrelocs;		/* Number of relocations */

  uint32_t numwrites;		/* Number of writes */

  uint32_t numexctblents;	/* Number of ex_table entries */
  uint32_t numpreexctblents;	/* Number of pre_ex_table entries */

  uint32_t numdeps;		/* Number of dependendencies */

  uint32_t taglen;		/* length of tags string */

  char __pad1[4];		/* round out to a multiple of 8 bytes */
};

#endif /* __XEN_PUBLIC_LIVE_PATCH_H__ */
