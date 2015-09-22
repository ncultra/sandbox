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



// sanity check parms
// make sure there is room
// update sandbox state (next_patch, sandbox_avail)
int apply_patch(struct patch *new_patch)
{
	return 0;
	
}


struct patch *alloc_patch(char *name, int size)
{
	struct patch *new_patch = calloc(1, sizeof(struct patch));
	if (! new_patch) {
		return NULL;
	}
	
	new_patch->patch_buf = aligned_alloc(0x400, size);
	
	if (new_patch->patch_buf == NULL) {
		goto exit_patch_buf;
	}
	strncpy(&new_patch->name[0], name, 0x40);
	return new_patch;
	
exit_patch_buf:
	free(new_patch->patch_buf);
	return NULL;
}


void make_sandbox_writeable(void *start, void *end) 
{
	
	if (mprotect(start, end - start, PROT_READ|PROT_EXEC|PROT_WRITE))
	{
		DMSG("memprotect failed, %i\n", errno);
		return;
		
	}
}
