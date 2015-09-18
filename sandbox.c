#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <memory.h>
#include <sys/mman.h>
#include <errno.h>
#include "sandbox.h"
extern long long patch_sandbox_start, patch_sandbox_end;

int main(int c, char **argv)
{
	

	void(*call_patch_sandbox)(void) = (void *)&patch_sandbox_start;

	printf ("\nmaking the patch sandbox writeable\n\n");
	if (mprotect((void *)&patch_sandbox_start, &patch_sandbox_end - &patch_sandbox_start, PROT_READ|PROT_EXEC|PROT_WRITE))
	{
		printf ("memprotect failed, %s\n", errno);
		exit -1;
		
	}

	printf ("writing to patch sandbox...\n\n");
	
	char *patch = (char *)&patch_sandbox_start + 0x0d;
	memset(patch, '1', 64);
	
	printf ("write completed, calling into the patch sandbox\n\n");
		
	call_patch_sandbox();
	
	printf("returned from the patch sandbox\n\n");
	       
	       
	return 0;
}
