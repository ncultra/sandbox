#include <sys/mman.h>
#include "sandbox.h"
__asm__(".global patch_sandbox_start");
__asm__(".global patch_sandbox_end");
__asm__(".align 0x1000");
__asm__("patch_sandbox_start:");
__asm__("jmp patch_sandbox_end");
__asm__(".fill 0x400");
__asm__(".align 8");
__asm__("patch_sandbox_end:");
__asm__("retq");

struct patch *patch_list = NULL;
uint64_t patch_cursor = 0;


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
	
	patch_cursor += (0x40 - 1);
	patch_cursor = __ALIGN_KERNEL(patch_cursor, 0x40);
	memcpy((void *)patch_cursor, (void *)new_patch->patch_buf, s);

	new_patch->flags |= PATCH_IN_SANDBOX;
	patch_cursor += s;

	if (new_patch->reloc_dest) {
		if (mprotect((reloc_ptr_t)new_patch->reloc_dest,
			     (size_t)new_patch->reloc_size + 0x40,
			     PROT_READ|PROT_EXEC|PROT_WRITE)){

			DMSG("Unable to write relocation record @ %p\n",
			     (void *)new_patch->reloc_dest);
			goto err_exit;
		}
		
		if (mlock((reloc_ptr_t)new_patch->reloc_dest, new_patch->reloc_size)) {
				DMSG("Unable to lock  relocation record @ %p\n",
				     (void *)new_patch->reloc_dest);
				goto err_exit;
		}

		// the reloc value should be a near jump "e9 0xaaaaaaaa"
		// OR the first 3 bytes of the current value of the dest into the reloc_data
		// TODO: add some awareness of the data size to be written and the read mask
		*(reloc_ptr_t)new_patch->reloc_data |=
			*(reloc_ptr_t)new_patch->reloc_dest & (uint64_t)0xffffff;
		
		smp_mb();
		*(reloc_ptr_t)new_patch->reloc_dest = *(reloc_ptr_t)new_patch->reloc_data;
		munlock((reloc_ptr_t)new_patch->reloc_dest, new_patch->reloc_size);
	}
	
	new_patch->flags |= PATCH_APPLIED;
	
	return 0;
err_exit:
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
	
	new_patch->patch_buf = aligned_alloc(0x40, size);
	
	if (new_patch->patch_buf == NULL) {
		goto exit_patch_buf;
	}
	strncpy(&new_patch->name[0], name, 0x40);
	new_patch->patch_size = size;
	return new_patch;
	
exit_patch_buf:
	free(new_patch->patch_buf);
exit_null:
	
	return NULL;
}


void free_patch(struct patch *p)
{

	if (p->patch_buf) {
		free(p->patch_buf);
		p->patch_buf = NULL;
	}

	free(p);
}



uint64_t make_sandbox_writeable(void *start, void *end) 
{
	if (mprotect(start, end - start, PROT_READ|PROT_EXEC|PROT_WRITE))
	{
		DMSG("memprotect failed, %i\n", errno);
		return 0;
	}
	return patch_sandbox_start;
}


uint64_t init_sandbox(void)
{
	uint64_t start = make_sandbox_writeable(&patch_sandbox_start,
						&patch_sandbox_end);
	if (start) {		
		patch_cursor = start;
	}
	return start;
}

	
