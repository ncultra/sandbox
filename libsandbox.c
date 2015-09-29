#include <sys/mman.h>
#include "sandbox.h"
__asm__(".global patch_sandbox_start");
__asm__(".global patch_sandbox_end");
__asm__(".align 0x1000");
__asm__("patch_sandbox_start:");
__asm__("jmp patch_sandbox_end");
__asm__(".fill 0x1000");
__asm__(".align 8");
__asm__("patch_sandbox_end:");
__asm__("retq");

struct patch *patch_list = NULL;
uint8_t *patch_cursor = NULL;



void viewsandbox_cursor(void *cursor)
{
	dump_sandbox(cursor, 64);
}


void viewsandbox(void *start, void *end)
{
	dump_sandbox(start, end - start);
}



// sanity check parms
// make sure there is room
// update sandbox cursor
int apply_patch(struct patch *new_patch)
{
	assert(get_sandbox_free() > new_patch->patch_size);
	int s = new_patch->patch_size;
	// pointer arithmetic needs to be rewritten, casting pointers means
	// that incrementing them is unpredictable
	//patch_cursor = (uint8_t *)ALIGN_POINTER((uintptr_t)patch_cursor, 0x40);

	
	memcpy((uint8_t*)patch_cursor, (uint8_t *)new_patch->patch_buf, s);
	new_patch->flags |= PATCH_IN_SANDBOX;
	patch_cursor += s;

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


//	*(uint64_t *)new_patch->reloc_data |=
//		*(uint64_t *)new_patch->reloc_dest & (uint64_t)0xffffff;
		
		smp_mb();

		for (int i = 0; i < PLATFORM_RELOC_SIZE; i++){
			
			*((uint8_t *)new_patch->reloc_dest + i) = new_patch->reloc_data[i];
		}

////		*(uint64_t *)new_patch->reloc_dest = *(uint64_t *)new_patch->reloc_data;

	
	new_patch->flags |= PATCH_APPLIED;
	
	return 0;
}

err_exit:
	DMSG("Unable to write relocation record @ %p\n", (void *)new_patch->reloc_dest);
	return -1;
}


struct patch *alloc_patch(char *name, uint64_t size)
{
	uint64_t avail = get_sandbox_free();
	
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
	
	printf ("sandbox start before alignment\n %016lx\n",(uint64_t)&patch_sandbox_start);
	printf ("sandbox end before alignment\n %016lx\n",(uint64_t)&patch_sandbox_end);
	p &= PLATFORM_PAGE_MASK;
	printf("page mask: %016lx\n", (uint64_t)PLATFORM_PAGE_MASK);
	
	printf ("sandbox start %016lx\n", (uint64_t)&patch_sandbox_start);
	printf ("page size: %016lx\n", (uint64_t)PLATFORM_PAGE_SIZE);
	printf("page-aligned address: %016lx\n", p);
	
	if (mprotect((void *)p, SANDBOX_ALLOC_SIZE - 1,
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

	
