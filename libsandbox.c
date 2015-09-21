#include <sys/mman.h>
#include "sandbox.h"



void make_sandbox_writeable(void *start, void *end) 
{
	
	if (mprotect(start, end - start, PROT_READ|PROT_EXEC|PROT_WRITE))
	{
		DMSG("memprotect failed, %s\n", errno);
		return;
		
	}
}
