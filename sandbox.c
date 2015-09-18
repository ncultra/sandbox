
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/mman.h>
#include <errno.h>
#include <getopt.h>
#include <errno.h>
#include "sandbox.h"
#include <memory.h>

 

extern long long patch_sandbox_start, patch_sandbox_end;

static int test_flag;


int main(int argc, char **argv)
{

	while (1)
	{
		// TODO: finish the options
		int c;
		static struct option long_options[] = {
			{"test", no_argument, &test_flag, 1},
			{0,0,0,0}
		};
		int option_index = 0;
		c = getopt_long(argc, argv, "t", long_options, &option_index);
		break;
		
	}
	
	
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
