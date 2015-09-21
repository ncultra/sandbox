#include <sys/mman.h>
#include "sandbox.h"
asm(".global patch_sandbox_start");
asm(".global patch_sandbox_end");
asm(".align 0x1000");
asm("patch_sandbox_start:");
asm("jmp patch_sandbox_end");
asm(".fill 0x400");
asm(".align 8");
asm("patch_sandbox_end:");
asm("retq");

void make_sandbox_writeable(void *start, void *end) 
{
	
	if (mprotect(start, end - start, PROT_READ|PROT_EXEC|PROT_WRITE))
	{
		DMSG("memprotect failed, %s\n", errno);
		return;
		
	}
}
