#include "sandbox.h"
static int test_flag = 0, server_flag = 0, client_flag = 0;

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

char *sandbox_sock = "sandbox-sock";


int usage(void) 
{
	printf("\n sandbox [options]\n");
	printf("\t --test: call into the sandbox\n");
	printf("\t --server: run as a server\n");
	printf("\t --client: run as a client\n");
	printf("\t --help: display this usage information\n");
	return 0;
}


char clsock[PATH_MAX];

int main(int argc, char **argv)
{

	while (1)
	{
		int cl;
		static struct option long_options[] = {
			{"test", no_argument, &test_flag, 1},
			{"help", no_argument, NULL, 0},
			{"symbols", no_argument, NULL, 0},
			{"server", no_argument, &server_flag, 1},
			{"client", required_argument, &client_flag, 1},
			{0,0,0,0}
		};
		int option_index = 0;
		cl = getopt_long(argc, argv, "thsc:", long_options, &option_index);
		if (cl == -1)
		    break;

		switch (cl) {
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
			break;
		case 's':  printf("%s\n", long_options[option_index].name);
			if (!strstr(long_options[option_index].name, "server")){
				server_flag = 1;
				printf("running as a server\n");
			}
			
			break;
		case 'c': printf("%s\n", long_options[option_index].name);
			if (!strstr(long_options[option_index].name, "client")) {
				client_flag = 1;
				printf("running as a client\n");
				snprintf(clsock, sizeof(clsock), "%s", optarg);
				
			}
			
			break;
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

	if (server_flag) {	
		struct listen l;
		pthread_t *pt;
		int sockfd;

		sockfd = listen_sandbox_sock(sandbox_sock);
		DMSG("listening socket: %d\n", sockfd);		
		//	ccode = accept_sandbox_sock(sockfd, &client_id);

		l.sock = sockfd;
		l.arg = NULL;
		pt = run_listener(&l);
		DMSG("server thread: %p\n", pt);
		while (1) {
			sleep(1);
		}
	}
	
	if(client_flag) {
		int c = 0xff, fd, ccode = SANDBOX_OK;;
		char *info;
		
		if (strlen(clsock)) 
		{
			DMSG("client connecting to %s\n", clsock);
			fd = client_func(clsock);
			DMSG("client file descriptor: %d\n", fd);
			DMSG("sending test req message: ccode %d\n", c);
			
			ccode = send_rr_buf(fd, SANDBOX_TEST_REQ, sizeof(c),
				    &c, SANDBOX_LAST_ARG);
			DMSG("send_rr_buf returned: %d\n", ccode);
			
			if (ccode == SANDBOX_OK) {
				uint16_t version, id;
				uint32_t len;
			
				ccode = read_sandbox_message_header(fd, &version,
								    &id, &len, NULL);
			

				info = get_sandbox_build_info(fd);
				if (info != NULL) {
					DMSG("%s\n", info);
					free(info);
				}
			}			
			close(fd);
		}
		
	}
			


	
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
	__asm__("jmp patched_stub_entry");
	
	
	
	return 0;
}

void patched_stub(void)
{
	__asm__("patched_stub_entry:");
	__asm__("patched_stub_entry_patch:");
	__asm__("patched_stub_entry_patch_patch:");
	__asm__("patched_stub_entry_patch_patch_patch:");
	__asm__("patched_stub_entry_patch_patch_patch_patch:");
	static int count = 0;
	printf("executing inside the patched code, count: %i\n", ++count);
	__asm__("patched_stub_exit:");
	
	exit(0);
	
}
