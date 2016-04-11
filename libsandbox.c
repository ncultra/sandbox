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

struct list_head patch_list;

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

	//TODO: use list macros
//	link_struct_patch(new_patch);
	
	return 0;
}

err_exit:
	DMSG("Unable to write relocation record @ %p\n", (void *)new_patch->reloc_dest);
	return -1;
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
