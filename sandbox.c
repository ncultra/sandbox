#include "sandbox.h"
static int test_flag;

struct patch *create_test_patch;
extern uint64_t _start;

void (*patched)(void);
void patched_stub(void);

#ifdef X86_64
// jmp far,  operand will change with every build
uint8_t jumpto[] = {0xff,0x17,0x04,0x00,0x0c};
// these bytes get written to the sandbox and executed by the jump
//  0xc3 is a near return, the rest is a nopq

__asm__("jmp patched_stub");

uint8_t patch_data[] = {0xc3, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00};

#endif

#ifdef PPC64LE

uint8_t jumpto[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uint8_t patch_data[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0};

#endif


int usage(void) 
{
	printf("\n sandbox [options]\n");
	printf("\t --test: call into the sandbox\n");
	printf("\t --help: display this usage information\n");
	printf("\t --symbols: show dynamic symbols\n");
	return 0;
}


int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;
	
	printf("name=%s (%d segments)\n", info->dlpi_name,
               info->dlpi_phnum);
	
	for (j = 0; j < info->dlpi_phnum; j++)
                printf("\t\t header %2d: address=%10p\n", j,
		       (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr));
	return 0;
}


int main(int argc, char **argv)
{

	while (1)
	{
		int c;
		static struct option long_options[] = {
			{"test", no_argument, &test_flag, 1},
			{"help", no_argument, NULL, 0},
			{"symbols", no_argument, NULL, 0},
			{0,0,0,0}
		};
		int option_index = 0;
		c = getopt_long(argc, argv, "ths", long_options, &option_index);
		if (c == -1)
		    break;

		switch (c) {
		case  't':
			if (strstr(long_options[option_index].name, "test") ) {
				test_flag = 1;
			}
			
			break;
		case 'h':
			if (!strstr(long_options[option_index].name, "help")) {
				usage();
				exit(1);	
			}
		case 's' : {
			struct dl_phdr_info search;
			c = reflect(&search, callback);
			
			exit(0);	
		}
		default:
			break;	
		}
		DMSG("selected option %s\n", long_options[option_index].name);
	}
	
	// init makes the sandbox area writeable
	init_sandbox(); // returns a cursor to the patch area
	DMSG("Current patch_cursor: %016lx\n", (uint64_t)patch_cursor);
	patched  = (void (*)(void))&patch_sandbox_start;
	DMSG(" patched symbol %p; _start %p\n", (void *)patched, (void *)&_start);
	DMSG("jump to: %p\n", (void *)patched_stub);
	
	DMSG("pid: %i\n", getpid());
	
	if (test_flag) {
		char *pname = strdup("pname");
		
		int err;
		
		DMSG (" replacement code: %lx\n", (uint64_t) jumpto[0]);

		DMSG("sandbox start %016lx\n",  (uint64_t)&patch_sandbox_start);
		DMSG("sandbox end   %016lx\n",  get_sandbox_end());
		DMSG("Sandbox is      %016lx bytes\n", get_sandbox_end() - (uint64_t)&patch_sandbox_start);
		
		DMSG("writing to patch sandbox...\n\n");

		// allocate and init the patch structure

		struct patch *p = (struct patch *)alloc_patch(pname, sizeof(patch_data));
		p->patch_dest = patch_cursor;
		p->reloc_dest = (uintptr_t)patched; // points to the "patched" function
		memcpy(p->reloc_data, jumpto, sizeof(jumpto));
		memcpy((uint8_t*)p->patch_buf, patch_data, sizeof(patch_data));
		p->patch_size = sizeof(patch_data);
		dump_sandbox(&patch_sandbox_start, 16);
				
		// apply the patch
		err = apply_patch(p);
		printf ("err = %d\n", err);
		dump_sandbox(&patch_sandbox_start, 16);
		DMSG("write completed, calling into the patch sandbox\n\n");
		
		patched();
		
		DMSG("\nreturned from the patch sandbox\n\n");
		dump_sandbox(main + 0x758, 16);

	}

	
	char c;
	
	while( (c = getchar()) ) {
		sleep(10);
	}
	
	__asm__("jmp patched_stub_entry");
	
	
	
	return 0;
}

void patched_stub(void)
{
	__asm__("patched_stub_entry:");
	
	static int count = 0;
	printf("executing inside the patched code, count: %i\n", ++count);
}
