
#include "sandbox.h"
static int test_flag;

struct patch *create_test_patch;
extern uint64_t _start;

void patched(void);


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
	
	
	// init makes the sandbox area writeable
	init_sandbox(); // returns a cursor to the patch area
	printf ("patch_cursor %016lx\n", (uint64_t)patch_cursor);
//	printf ("----------------- sandbox --------------------\n");
//	viewsandbox(&patch_sandbox_start, &patch_sandbox_end);
//	printf ("----------------- cursor ---------------------\n");
//	viewsandbox_cursor(&patch_cursor);
	
	void(*call_patch_sandbox)(void) = (void *)patch_sandbox_start;

	patched();

	printf("%p %p\n", (void *)patched, (void *)&_start);
	
	
	if (test_flag) {
		uint8_t jumpto[8] = {0xe9, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 00};
		uint8_t patch_data[] = {0x55, 0x48, 0x89, 0xe5, 0xbf, 0xc8, 0x3b, 0x40, 0x00,
				      0xe8, 0x47, 0xf5, 0xff, 0xff, 0x5d, 0xc3};
		char *pname = strdup("pname");
		
		int err;
		
		printf (" replacement code: %lx\n", (uint64_t) jumpto[0]);

		printf("sandbox start %016lx\n",  (uint64_t)&patch_sandbox_start);
		printf("sandbox end   %016lx\n",  (uint64_t)&patch_sandbox_end);
		DMSG("Sandbox is      %016lx bytes\n", (uint64_t)&patch_sandbox_end - (uint64_t)&patch_sandbox_start);
		
		DMSG("writing to patch sandbox...\n\n");

		// allocate and init the patch structure

		struct patch *p = alloc_patch(pname, sizeof(patch_data));
		p->patch_dest = patch_cursor;
		p->reloc_dest = (uint8_t *)main + 0x78;
		memcpy(&p->reloc_data[0], jumpto, sizeof(jumpto));
		memcpy(&p->patch_buf[0], patch_data, sizeof(patch_data));
		p->patch_size = sizeof(patch_data);

		// apply the patch
		err = apply_patch(p);
		printf ("err = %d\n", err);
		
		//char *patch = (char *)&patch_sandbox_start + 0x0d;
		//memset(patch, '1', 64);
	
		DMSG("write completed, calling into the patch sandbox\n\n");
		
		call_patch_sandbox();

		//	viewsandbox(&patch_sandbox_start, &patch_sandbox_end);
		//	viewsandbox_cursor(&patch_cursor);
		DMSG("\nreturned from the patch sandbox\n\n");
	}
	       
	return 0;
}

void patched(void)
{
	printf("executing inside the patched code\n");
	
}
