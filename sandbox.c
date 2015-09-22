
#include "sandbox.h"
static int test_flag;


int usage(void) 
{
	printf("\n: sandbox [options]\n");
	printf("\t --test: call into the sandbox\n");
	printf("\t --help: display this usage information\n");
	return 0;
}

int main(int argc, char **argv)
{

	while (1)
	{
		int c;
		static struct option long_options[] = {
			{"test", no_argument, &test_flag, 1},
			{0,0,0,0}
		};
		int option_index = 0;
		c = getopt_long(argc, argv, "t", long_options, &option_index);
		if (c == -1)
		    break;

		switch (c) {
		case  't':
			if (strstr(long_options[option_index].name, "test") ) {
				test_flag = 1;
			} else {
				break;
			}
		case 'h':
			if (!strstr(long_options[option_index].name, "help")) {
				usage();
				break;	
			}
		default:
			break;	
		}
		DMSG("seleted option %s\n", long_options[option_index].name);
	}
	
	

	void(*call_patch_sandbox)(void) = (void *)&patch_sandbox_start;
	make_sandbox_writeable((void *)&patch_sandbox_start, (void *)&patch_sandbox_end);
	
	if (test_flag) {
		DMSG("Sandbox is %ul bytes\n", &patch_sandbox_end - &patch_sandbox_start);
		
		
		DMSG("writing to patch sandbox...\n\n");
	
		char *patch = (char *)&patch_sandbox_start + 0x0d;
		memset(patch, '1', 64);
	
		DMSG("write completed, calling into the patch sandbox\n\n");
		
		call_patch_sandbox();
	
		DMSG("returned from the patch sandbox\n\n");
	}
	       
	return 0;
}
