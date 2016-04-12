#define _GNU_SOURCE
#include <link.h>
#include <libelf.h>
#include <sys/mman.h>
#include "sandbox.h"

/************************************************************
 * The .align instruction has a different syntax on X86_64
 * than it does on PPC64. 
 *
 * On X86_64, the operand to .align is an absolute address.
 * On PP64, the operand is an exponent of base 2.
 * .align 8 on X86 is equal to .align 3 on PPC (2^3 = 8.)
 *
 ************************************************************/

uint64_t fill = PLATFORM_ALLOC_SIZE;
__asm__(".text");

__asm__(".global patch_sandbox_start");

#ifdef X86_64
__asm__(".align 0x1000");
#endif
#ifdef  PPC64LE
__asm__(".align 0x0c");
#endif
__asm__("patch_sandbox_start:");
#ifdef X86_6
__asm__("jmp patch_sandbox_end");
__asm__(".fill 0x1000");
__asm__(".align 8");
#endif
#ifdef PPC64LE
__asm__("b patch_sandbox_end");
__asm__(".fill PLATFORM_ALLOC_SIZE");
__asm__(".align 3");

#endif
__asm__("patch_sandbox_end:");

#ifdef X86_64
__asm__("retq");
#endif

#ifdef PPC64LE
__asm__("blr");
#endif

LIST_HEAD(patch_list);


uint8_t *patch_cursor = NULL;


uint64_t get_sandbox_start(void)
{
	return  (uint64_t)&patch_sandbox_start;
}

uint64_t get_sandbox_end(void)
{
	return PLATFORM_ALLOC_SIZE + get_sandbox_start();
	
}


int apply_patch(struct patch *new_patch)
{
	assert(get_sandbox_free() > new_patch->patch_size);
        assert(new_patch->patch_size < MAX_PATCH_SIZE);
        int s = new_patch->patch_size;

	patch_cursor = (uint8_t *)ALIGN_POINTER((uintptr_t)patch_cursor, 0x40);

	
	memcpy((uint8_t*)patch_cursor, (uint8_t *)new_patch->patch_buf, s);
	new_patch->flags |= PATCH_IN_SANDBOX;
	patch_cursor += s;
	patch_cursor = (uint8_t *)ALIGN_POINTER((uintptr_t)patch_cursor, 0x40);
	

	if (new_patch->reloc_dest) {
		uint64_t p = (uint64_t)new_patch->reloc_dest;
		p &= PLATFORM_PAGE_MASK;
		if (mprotect((void *)p , PLATFORM_PAGE_SIZE,
			     PROT_READ|PROT_EXEC|PROT_WRITE)){			
			perror("err: ");
			
			assert(0);
			goto err_exit;
	}

// the reloc value should be a near jump "e9 0xaaaaaaaa"
// OR the first 3 bytes of the current value of the dest into the reloc_data
// TODO: add some awareness of the data size to be written and the read mask
		
		smp_mb();

		*(uint64_t *)new_patch->reloc_dest = *(uint64_t *)new_patch->reloc_data;
		DMSG("relocated to:\n");
		dump_sandbox((void *)new_patch->reloc_dest, 16);
		DMSG("patched  instructions\n");
		dump_sandbox((void *)new_patch->patch_buf, 16);
	
	new_patch->flags |= PATCH_APPLIED;

	list_add(&patch_list, &new_patch->l);
	return 0;
}

err_exit:
	DMSG("Unable to write relocation record @ %p\n", (void *)new_patch->reloc_dest);
	return -1;
}


static int xenlp_apply(void *arg)
{
    struct xenlp_apply apply;
    unsigned char *blob = NULL;
    struct xenlp_patch_write *writes;
    size_t i;
    struct applied_patch *patch;
    int32_t relocrel = 0;
    char sha1[41];

    
    /* FIXME: Manipulating arg.p seems a bit ugly */

    /* Skip over struct xenlp_apply */
    arg.p = (unsigned char *)arg.p + sizeof(apply);

    /* Do some initial sanity checking */
    if (apply.bloblen > MAX_PATCH_SIZE) {
        printk("live patch size %u is too large\n", apply.bloblen);
        return -EINVAL;
    }

    if (apply.numwrites == 0) {
        printk("need at least one patch\n");
        return -EINVAL;
    }

    patch = xmalloc(struct applied_patch);
    if (!patch)
        return -ENOMEM;

    /* FIXME: Memory allocated for patch can leak in case of error */

    /* Blobs are optional */
    if (apply.bloblen) {
        unsigned int pageorder;

        pageorder = get_order_from_bytes(apply.bloblen);
        blob = allocate_map_mem(pageorder);
        if (!blob)
            return -ENOMEM;

        /* FIXME: Memory allocated for blob can leak in case of error */

        /* Copy blob to hypervisor was copy from guest */

        /* Skip over blob */
        arg.p = (unsigned char *)arg.p + apply.bloblen;

        /* Calculate offset of relocations */
        relocrel = (uint64_t)blob - apply.refabs;
    }

    /* Read relocs */
    if (apply.numrelocs) {
        uint32_t *relocs;

        relocs = xmalloc_array(uint32_t, apply.numrelocs);
        if (!relocs)
            return -ENOMEM;

	/* was copy from guest */

        arg.p = (unsigned char *)arg.p + (apply.numrelocs * sizeof(relocs[0]));

        for (i = 0; i < apply.numrelocs; i++) {
            uint32_t off = relocs[i];
            if (off > apply.bloblen - sizeof(int32_t)) {
                printk("invalid off value %d\n", off);
                return -EINVAL;
            }

            /* blob -> HV .text */
            *((int32_t *)(blob + off)) -= relocrel;
        }

        xfree(relocs);
    }

    /* Read writes */
    writes = xmalloc_array(struct xenlp_patch_write, apply.numwrites);
    if (!writes)
        return -ENOMEM;

    /* was copy from guest */

    /* Move over all of the writes */
    arg.p = (unsigned char *)arg.p + (apply.numwrites * sizeof(writes[0]));

    /* Verify writes and apply any relocations in writes */
    for (i = 0; i < apply.numwrites; i++) {
        struct xenlp_patch_write *pw = &writes[i];
        char off = pw->dataoff;

        if (pw->hvabs < (uint64_t)_start || pw->hvabs >= lp_tail) {
            printk("invalid hvabs value %lx\n", pw->hvabs);
            return -EINVAL;
        }

        if (off < 0)
            continue;

        /* HV .text -> blob */
        switch (pw->reloctype) {
        case XENLP_RELOC_UINT64:
            if (off > sizeof(pw->data) - sizeof(uint64_t)) {
                printk("invalid dataoff value %d\n", off);
                return -EINVAL;
            }

            *((uint64_t *)(pw->data + off)) += relocrel;
            break;
        case XENLP_RELOC_INT32:
            if (off > sizeof(pw->data) - sizeof(int32_t)) {
                printk("invalid dataoff value %d\n", off);
                return -EINVAL;
            }

            *((int32_t *)(pw->data + off)) += relocrel;
            break;
        default:
            printk("unknown reloctype value %u\n", pw->reloctype);
            return -EINVAL;
        }
    }

    /* Nothing should be possible to fail now, so do all of the writes */
    swap_trampolines(writes, apply.numwrites);

    /* Record applied patch */
    patch->blob = blob;
    memcpy(patch->sha1, apply.sha1, sizeof(patch->sha1));
    patch->numwrites = apply.numwrites;
    patch->writes = writes;
    patch->next = NULL;
    if (!lp_patch_head)
        lp_patch_head = patch;
    if (lp_patch_tail)
        lp_patch_tail->next = patch;
    lp_patch_tail = patch;

    bin2hex(apply.sha1, sizeof(apply.sha1), sha1, sizeof(sha1));
    printk("successfully applied patch %s\n", sha1);

    return 0;
}

struct patch *alloc_patch(char  *name, uint64_t size)
{
	uint64_t avail = get_sandbox_free();
	DMSG("%08lx available in sandbox\n", avail);
	
	if (avail < size ) {
		DMSG("Not enough room to apply patch: %ld available, %ld needed\n",
		     get_sandbox_free(),
		     size);
		goto exit_null;;
	}
	
	
	struct patch *new_patch = calloc(1, sizeof(struct patch));
	if (! new_patch) {
		goto exit_null;;
	}
	
	new_patch->patch_buf = (uintptr_t)aligned_alloc(0x40, size);
	if (!new_patch->patch_buf) {
		goto exit_patch_buf;
	}
	strncpy(new_patch->name, name, 0x40 - 1);
	new_patch->patch_size = size;
	return new_patch;
	
exit_patch_buf:
	if (new_patch->patch_buf)
		free((uint8_t *)new_patch->patch_buf);
exit_null:
	return NULL;
}


void free_patch(struct patch *p)
{

	if (p->patch_buf) {
		free((uint8_t *)p->patch_buf);
		p->patch_buf = 0L;
	}

	free(p);
}



uint8_t *make_sandbox_writeable(void) 
{

	
	uint64_t p = (uint64_t)&patch_sandbox_start;
	
	DMSG ("sandbox start before alignment\n %016lx\n",(uint64_t)&patch_sandbox_start);
	p &= PLATFORM_PAGE_MASK;
	DMSG("page mask: %016lx\n", (uint64_t)PLATFORM_PAGE_MASK);
	
	DMSG ("sandbox start %016lx\n", (uint64_t)&patch_sandbox_start);
	DMSG ("page size: %016lx\n", (uint64_t)PLATFORM_PAGE_SIZE);
	printf("page-aligned address: %016lx\n", p);
	
	if (mprotect((void *)p, SANDBOX_ALLOC_SIZE,
		     PROT_READ|PROT_EXEC|PROT_WRITE)) {
		DMSG("memprotect failed, %i\n", errno);
		perror("err: ");
		
	}
	return (uint8_t *)p;
}


void init_sandbox(void)
{
	make_sandbox_writeable(); 
	patch_cursor = (uint8_t *)&patch_sandbox_start;
}



int reflect(struct dl_phdr_info *info,
	    int (*cb)(struct dl_phdr_info *i, size_t s, void *data))
{
	dl_iterate_phdr(cb, NULL);
	
	return 0;

}
