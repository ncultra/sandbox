#include "sandbox.h"
static int test_flag;

struct patch *create_test_patch;
extern uint64_t _start;

void (*patched)(void);
void patched_stub(void);

#ifdef X86_64
// these bytes should cause a near jump to the sandbox
uint8_t jumpto[] = {0xe9, 0x0f, 0xfd, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00};

// these bytes get written to the sandbox and executed by the jump
//  0xc3 is a near return
uint8_t patch_data[] = {0xc3, 0x48, 0x89, 0xe5, 0xbf, 0xc8, 0x3b, 0x40, 0x00,
			0xff, 0x00, 0x47, 0xf5, 0xff, 0xff, 0x5d, 0xc3};
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
	
	char c;
	
	while( (c = getchar()) ) {
		sleep(10);
	}
	
	
	if (test_flag) {
		char *pname = strdup("pname");
		
		int err;
		
		DMSG (" replacement code: %lx\n", (uint64_t) jumpto[0]);

		DMSG("sandbox start %016lx\n",  (uint64_t)&patch_sandbox_start);
		DMSG("sandbox end   %016lx\n",  (uint64_t)&patch_sandbox_end);
		DMSG("Sandbox is      %016lx bytes\n", (uint64_t)&patch_sandbox_end - (uint64_t)&patch_sandbox_start);
		
		DMSG("writing to patch sandbox...\n\n");

		// allocate and init the patch structure

		struct patch *p = (struct patch *)alloc_patch(pname, sizeof(patch_data));
		p->patch_dest = patch_cursor;
		p->reloc_dest = (uintptr_t)&patched; // points to the "patched" function
		memcpy(p->reloc_data, jumpto, sizeof(jumpto));
		memcpy((uint8_t*)p->patch_buf, patch_data, sizeof(patch_data));
		p->patch_size = sizeof(patch_data);
		dump_sandbox(&patch_sandbox_start, 16);
				
		// apply the patch
		err = apply_patch(p);
		printf ("err = %d\n", err);
		DMSG("write completed, calling into the patch sandbox\n\n");
		dump_sandbox(&patch_sandbox_start, 16);
		
		patched_stub();
		patched();

		DMSG("\nreturned from the patch sandbox\n\n");
		dump_sandbox(main + 0x758, 16);

	}
	       
	return 0;
}

void patched_stub(void)
{
	static int count = 0;
	printf("executing inside the patched code, count: %i\n", ++count);
}
