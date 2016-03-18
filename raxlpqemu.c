/*****************************************************************
 * Copyright 2016 Rackspace, Inc.
 *
 * listen on a unix domain socket for incoming patches
 ****************************************************************/
#include "sandbox.h"

/* these are not used by any other obj, so keep the #includes here */
#include <zlib.h>
#include <libelf.h>
#include <openssl/sha.h>

static int info_flag, list_flag, apply_flag, remove_flag;
static char filepath[PATH_MAX];
static char patch_basename[PATH_MAX];
static inline char *get_patch_name(char *path)
{
	strncpy(patch_basename, basename(path), PATH_MAX - 1);
	return patch_basename;
}

void usage(void)
{
	printf("\nraxlpqemu --info --list --apply <patch> --remove <patch> --help\n");
	exit(0);	
}

int open_patch_file(char *path)
{
	int patchfd;
	patchfd = open(path, O_RDONLY);
	if (patchfd < 0) {
		DMSG("error: open(%s): %m\n", path);
		return SANDBOX_ERR_BAD_FD;
	}
	strncpy(filepath, path, PATH_MAX -1);
	return patchfd;
}




int main(int argc, char **argv)
{
	
	while (1)
	{
		if (argc < 2)
			usage();
		
		int c;
		static struct option long_options[] = {
			{"dummy-for-short-option", no_argument, NULL, 0},
			{"info", no_argument, &info_flag, 1},
			{"list", no_argument, &list_flag, 1},
			{"apply", required_argument, &apply_flag, 1},
			{"remove", required_argument, &remove_flag, 1},
			{"help", no_argument, NULL, 0},
			{0,0,0,0}
		};
		int option_index = 0;
		c = getopt_long(argc, argv, "ila:r:h", long_options, &option_index);
		if (c == -1) {
			break;
		}
		
	restart_long:
		switch (option_index) {
		case 0:
			switch (c) {
			case  'i':
				option_index = 1;
				goto restart_long;
			case 'l':
				option_index = 2;
				goto restart_long;
			case 'a' :
				option_index = 3;
				goto restart_long;
			case 'r':
				option_index = 4;
				goto restart_long;
			case 'h':
				option_index = 5;
				goto restart_long;
			default:
				break;
				usage();			
			}
		case 1:
		case 2:
			DMSG("selected option %s\n", long_options[option_index].name);
			break;
		case 3:
		case 4: 
		{
			
			int pfd;
			char *fdname;
			DMSG("selected option %s with arg %s\n",
			     long_options[option_index].name, optarg);

			fdname  = get_patch_name(optarg);
			DMSG("patch file name: %s\n", fdname);			
			if ((pfd = open_patch_file(optarg)) == SANDBOX_ERR_BAD_FD)
				exit(0);
			DMSG("patch file fd %d\n", pfd);
			
		}
		
			
			break;
		case 5:
			usage();
		default:
			break;
		}
	}



	printf("bye\n");	
}
