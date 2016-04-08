/*****************************************************************
 * Copyright 2016 Rackspace, Inc.
 *
 * listen on a unix domain socket for incoming patches
 ****************************************************************/
/* these are not used by any other obj, so keep the #includes here */

#include <zlib.h>
#include <libelf.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "live_patch.h"
#include "util.h"

#include "sandbox.h"

#define XSPATCH_COOKIE	"XSPATCH2"

static int info_flag, list_flag, apply_flag, remove_flag;
static char filepath[PATH_MAX];
static char patch_basename[PATH_MAX];

static char sockname[PATH_MAX];
static int sockfd;

static inline char *get_patch_name(char *path)
{
	
	strncpy(patch_basename, basename(path), PATH_MAX - 1);
	return patch_basename;
}

void usage(void)
{
	printf("\nraxlpqemu --info --list --apply <patch> \
--remove <patch> --socket --help\n");
	exit(0);	
}

int open_patch_file(char *path)
{
	int patchfd;

	if (!strlen(path)) {
		DMSG("filepath is not initialized\n");
		return SANDBOX_ERR_BAD_FD;
	}	
	patchfd = open(path, O_RDONLY);
	if (patchfd < 0) {
		DMSG("error: open(%s): %m\n", path);
		return SANDBOX_ERR_BAD_FD;
	}
	return patchfd;
}

int string2sha1(const char *string, unsigned char *sha1)
{
    int i;
    /* Make sure first 40 chars of string are composed of only hex digits */
    for (i = 0; i < 40; i += 2) {
        if (sscanf(string + i, "%02x", (int*)(&sha1[i / 2])) != 1) {
            fprintf(stderr, "error: not a valid sha1 string: %s\n", string);
            return -1;
        }
    }
    return 0;
}

int extract_sha1_from_filename(unsigned char *sha1, size_t sha1len,
                               const char *filename)
{

    /* Make sure suffix is .raxlpxs */
    if (strstr(filename, ".raxlpxs") == NULL) {
        fprintf(stderr, "error: missing .raxlpxs extension: filename must be of form <sha1>.raxlpxs\n");
        return -1;
    }

    /* Make sure filename length is 48: 40 (<sha1>) + 8 ('.raxlpxs') */
    if (strlen(filename) != 48) {
        fprintf(stderr, "error: filename must be of form <sha1>.raxlpxs\n");
        return -1;
    }

    return string2sha1(filename, sha1);
}


static void bin2hex(unsigned char *bin, size_t binlen, char *buf,
                    size_t buflen)
{
    static const char hexchars[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < binlen; i++, bin++) {
        /* Ensure we can fit two characters and the terminating nul */
        if (buflen >= 3) {
            *buf++ = hexchars[(*bin >> 4) & 0x0f];
            *buf++ = hexchars[*bin & 0x0f];

            buflen -= 2;
        }
    }

    if (buflen)
        *buf = 0;
}

/* TODO: add the sandbox pid to the name so there can be more than one. */
/*     "/var/run/sandbox.getpid()" */

/* use a wrapper function so we can eventually support other media beyond */
/* a domain socket, eg sysfs file */
int connect_to_sandbox(char *sandbox_name)
{
	return client_func(sandbox_name);	
}

/* request message has only the header (including message id) */
/* reply message has header, buflen, and buf */
inline char * get_sandbox_build(int fd)
{
	char  *info = get_sandbox_build_info(fd);
	if (info != NULL)
		DMSG("%s\n", info);
	return info;
}


int load_patch_file(int fd, char *filename, struct xpatch *patch);
static inline char *get_qemu_version(void);
static inline char *get_qemu_date(void);

int cmd_apply(int fd)
{
    int pfd;
    char *filename;
    struct xpatch patch;

    filename = get_patch_name(filepath);
    
    pfd = open_patch_file(filepath);
    if (pfd < 0) {
	    DMSG("error opening patch file %s\n", filepath);
	    return SANDBOX_ERR_BAD_FD;
    }
    
    if (load_patch_file(pfd, filename, &patch) < 0) {
	    DMSG("error parsing patch file %s\n", filename);
	    return SANDBOX_ERR_PARSE;;
    }
    
    DMSG("Getting QEMU/sandbox info\n");
    
    char *qemu_version = get_qemu_version();
    char *qemu_compile_date = get_qemu_date();
    if (!strlen(qemu_version) || !strlen(qemu_compile_date)) {
	    DMSG("error getting version and complilation data\n");
	    return SANDBOX_ERR_RW;	    
    }

 
    printf("  QEMU Version: %s\n", qemu_version);
    printf("  QEMU Compile Date: %s\n", qemu_compile_date);

    printf("\n");
    printf("Patch Applies To:\n");
    printf("  QEMU Version: %s\n", patch.xenversion);
    printf("  QEMU  Compile Date: %s\n", patch.xencompiledate);
    printf("\n");

    return SANDBOX_OK;
}

#if 0
    if (strcmp(rxenversion, patch.xenversion) != 0 ||
        strcmp(rxencompiledate, patch.xencompiledate) != 0) {
        fprintf(stderr, "error: patch does not match hypervisor build\n");
        return -1;
    }

    /* Perform some sanity checks */
    if (patch.crowbarabs != 0) {
        fprintf(stderr, "error: cannot handle crowbar style patches\n");
        return -1;
    }

    if (patch.numchecks > 0) {
        fprintf(stderr, "error: cannot handle prechecks\n");
        return -1;
    }

    /* FIXME: Handle hypercall table writes too */
    if (patch.numtables > 0) {
        fprintf(stderr, "error: cannot handle table writes, yet\n");
        return -1;
    }

    struct xenlp_patch_info *info = NULL;
    /* Do a list first and make sure patch isn't already applied yet */
    if (find_patch(xch, patch.sha1, sizeof(patch.sha1), &info) < 0) {
        fprintf(stderr, "error: could not search for patches\n");
        return -1;
    }
    if (info) {
        printf("Patch already applied, skipping\n");
        return 0;
    }

    /* Convert into a series of writes for the live patch functionality */
    uint32_t numwrites = patch.numfuncs;
    struct xenlp_patch_write writes[numwrites];
    memset(writes, 0, sizeof(writes));

    size_t i;
    for (i = 0; i < patch.numfuncs; i++) {
        struct function_patch *func = &patch.funcs[i];
        struct xenlp_patch_write *pw = &writes[i];

        pw->hvabs = func->oldabs;

        /* Create jmp trampoline */
        /* jmps are relative to next instruction, so subtract out 5 bytes
         * for the jmp instruction itself */
        int32_t jmpoffset = (patch.refabs + func->newrel) - func->oldabs - 5;

        pw->data[0] = 0xe9;		/* jmp instruction */
        memcpy(&pw->data[1], &jmpoffset, sizeof(jmpoffset));

        pw->reloctype = XENLP_RELOC_INT32;
        pw->dataoff = 1;

        printf("Patching function %s @ %llx\n", func->funcname, func->oldabs);
    }

    size_t buflen = fill_patch_buf(NULL, &patch, numwrites, writes);
    unsigned char *buf = _zalloc(buflen);
    buflen = fill_patch_buf(buf, &patch, numwrites, writes);

    int ret = do_lp_apply(xch, buf, buflen);
    if (ret < 0) {
        fprintf(stderr, "failed to patch hypervisor: %m\n");
        return -1;
    }

    char sha1str[41];
    bin2hex(patch.sha1, sizeof(patch.sha1), sha1str, sizeof(sha1str));
    printf("\nSuccessfully applied patch %s\n", sha1str);
    return 0;
}
#endif


int load_patch_file(int fd, char *filename, struct xpatch *patch)
{
    if (extract_sha1_from_filename(patch->sha1, sizeof(patch->sha1),
                                   filename) < 0)
        return -1;

    /* Calculate SHA1 hash and verify it matches filename */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "%s: stat(): %m\n", filename);
        return -1;
    }

    SHA_CTX sha1;
    SHA1_Init(&sha1);
    size_t bytesread = 0;
    while (bytesread < st.st_size) {
        unsigned char buf[4096];
        size_t readsize = sizeof(buf);
        if (st.st_size - bytesread < readsize)
            readsize = st.st_size - bytesread;

        if (_read(filename, fd, buf, readsize) < 0)
            return -1;

        SHA1_Update(&sha1, buf, readsize);
        bytesread += readsize;
    }
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &sha1);

    if (memcmp(patch->sha1, hash, sizeof(patch->sha1)) != 0) {
        char hex[SHA_DIGEST_LENGTH * 2 + 1];
        fprintf(stderr, "%s: hash mismatch\n", filename);
        bin2hex(hash, sizeof(hash), hex, sizeof(hex));
        fprintf(stderr, "  calculated %s\n", hex);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);

    char signature[8];
    if (_read(filename, fd, signature, sizeof(signature)) < 0)
        return -1;

    if (memcmp(signature, XSPATCH_COOKIE, sizeof(signature))) {
        fprintf(stderr, "%s: invalid signature\n", filename);
        return -1;
    }

    /* Read Xen version and compile date */
    if (_read(filename, fd, patch->xenversion,
              sizeof(patch->xenversion)) < 0)
        return -1;
    if (_read(filename, fd, patch->xencompiledate,
              sizeof(patch->xencompiledate)) < 0)
        return -1;

    /* Only used for crowbar, ignored in this utility */
    if (_readu64(filename, fd, &patch->crowbarabs) < 0)
        return -1;

    /* Virtual address used for first-stage relocation */
    if (_readu64(filename, fd, &patch->refabs) < 0)
        return -1;

    /* Pull the blob out */
    if (_readu32(filename, fd, &patch->bloblen) < 0)
        return -1;

    patch->blob = _zalloc(patch->bloblen);
    if (_read(filename, fd, patch->blob, patch->bloblen) < 0)
        return -1;

    /* Pull out second-stage relocations */
    if (_readu16(filename, fd, &patch->numrelocs) < 0)
        return -1;

    patch->relocs = _zalloc(patch->numrelocs * sizeof(uint32_t));
    size_t i;
    for (i = 0; i < patch->numrelocs; i++) {
        if (_readu32(filename, fd, &patch->relocs[i]) < 0)
            return -1;
    }

    /* Pull out check data. Only used for crowbar */
    if (_readu16(filename, fd, &patch->numchecks) < 0)
        return -1;

    patch->checks = _zalloc(sizeof(struct check) * patch->numchecks);
    for (i = 0; i < patch->numchecks; i++) {
        struct check *check = &patch->checks[i];

        if (_readu64(filename, fd, &check->hvabs) < 0)
            return -1;
        if (_readu16(filename, fd, &check->datalen) < 0)
            return -1;

        check->data = _zalloc(check->datalen);
        if (_read(filename, fd, check->data, check->datalen) < 0)
            return -1;
    }

    /* Pull out function to patch */
    if (_readu16(filename, fd, &patch->numfuncs) < 0)
        return -1;

    patch->funcs = _zalloc(patch->numfuncs * sizeof(patch->funcs[0]));
    for (i = 0; i < patch->numfuncs; i++) {
        struct function_patch *func = &patch->funcs[i];

        uint16_t size;
        if (_readu16(filename, fd, &size) < 0)
            return -1;
        func->funcname = _zalloc(size + 1);
        if (_read(filename, fd, func->funcname, size) < 0)
            return -1;

        if (_readu64(filename, fd, &func->oldabs) < 0)
            return -1;
        if (_readu32(filename, fd, &func->newrel) < 0)
            return -1;
    }

    /* Pull out table patches. Only used for crowbar currently */
    if (_readu16(filename, fd, &patch->numtables) < 0)
        return -1;

    patch->tables = _zalloc(sizeof(struct table_patch) * patch->numtables);
    for (i = 0; i < patch->numtables; i++) {
        struct table_patch *table = &patch->tables[i];

        uint16_t tablenamelen;
        if (_readu16(filename, fd, &tablenamelen) < 0)
            return -1;

        table->tablename = _zalloc(tablenamelen + 1);
        if (_read(filename, fd, table->tablename, tablenamelen) < 0)
            return -1;

        if (_readu64(filename, fd, &table->hvabs) < 0)
            return -1;
        if (_readu16(filename, fd, &table->datalen) < 0)
            return -1;

        table->data = _zalloc(table->datalen);
        if (_read(filename, fd, table->data, table->datalen) < 0)
            return -1;
    }

    close(fd);

    return 0;
}

#define COUNT_INFO_STRINGS 6
#define INFO_STRING_LEN 255
#define INFO_SHA_INDEX 0
#define INFO_COMPILE_INDEX 1
#define INFO_FLAGS_INDEX 2
#define INFO_DATE_INDEX 3
#define INFO_TAG_INDEX 4
#define INFO_VER_INDEX 5
char info_strings[COUNT_INFO_STRINGS][INFO_STRING_LEN + 1];

#define INFO_CHECK()				\
	if (strnlen(info_strings[0], INFO_STRING_LEN) < 1)	\
		get_info_strings(sockfd, 0);


/* when display is set print the info strings */
int get_info_strings(int fd, int display)
{
	char *info_buf, *info_buf_save, *p;
	int index = 0;
	
	if (fd < 0) {
		DMSG("get_info was passed a bad socket\n");
		return SANDBOX_ERR_BAD_FD;
	}
	
	info_buf =  get_sandbox_build_info(fd);
	if (info_buf == NULL) {
		DMSG("unable to get info strings\n");
		return SANDBOX_ERR_RW;
	}

	/* split the long string into separate strings*/
	p = strtok_r(info_buf, "\n", &info_buf_save);
	for (index = 0; index < COUNT_INFO_STRINGS && p != NULL; index++) {	
		strncpy(info_strings[index], p, INFO_STRING_LEN);
		if (display)
			printf("%s\n", info_strings[index]);
		
		p = strtok_r(NULL, "\n", &info_buf_save);
	}
	if (index <  COUNT_INFO_STRINGS - 1) {
		DMSG("error parsing info strings, index: %d\n", index);
		return SANDBOX_ERR_PARSE;
	}
	
	return SANDBOX_OK;
}


static inline char * get_qemu_sha(void)
{
	INFO_CHECK();
	return info_strings[INFO_SHA_INDEX];
}


static inline char * get_qemu_compile(void)
{
	INFO_CHECK();
	return info_strings[INFO_COMPILE_INDEX];
}

static inline char * get_qemu_flags(void)
{
	INFO_CHECK();
	return info_strings[INFO_FLAGS_INDEX];
}

static inline char * get_qemu_date(void)
{
	INFO_CHECK();
	return info_strings[INFO_DATE_INDEX];	
}

static inline char * get_qemu_tag(void)
{
	INFO_CHECK();
	return info_strings[INFO_TAG_INDEX];
}


static inline char *get_qemu_version(void) 
{
	INFO_CHECK();
	return info_strings[INFO_VER_INDEX];
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
			{"socket", required_argument, 0, 0},
			{"help", no_argument, NULL, 0},
			{0,0,0,0}
		};
		int option_index = 0;
		c = getopt_long(argc, argv, "ila:r:s:h", long_options, &option_index);
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
			case 's':
				option_index = 5;
				goto restart_long;
			case 'h':
				option_index = 6;
				goto restart_long;
			default:
				break;
				usage();			
			}
			DMSG("selected option %s\n", long_options[option_index].name);
		case 1:
			break;
			
		case 2:
			break;
			
		case 3:
		{
			printf("%s\n", optarg);
			
			strncpy(filepath, optarg, sizeof(filepath) - 1);
			DMSG("stored path of the patch file: %s\n", filepath);
			

			/* save patch apply flag and patch path to global vars */
			/* move this code into cmd_apply */
			/* int pfd; */
			/* char *fdname; */
			/* struct xpatch patch; */
			
			/* DMSG("selected option %s with arg %s\n", */
			/*      long_options[option_index].name, optarg); */

			/* fdname  = get_patch_name(optarg); */
			/* DMSG("patch file name: %s\n", fdname);			 */
			/* if ((pfd = open_patch_file(optarg)) == SANDBOX_ERR_BAD_FD) */
			/* 	exit(0); */
			/* DMSG("patch file fd %d\n", pfd); */

			/* if (load_patch_file(pfd, fdname, &patch) < 0) { */
			/* 	return SANDBOX_ERR_BAD_FD; */
			/* }			 */
			/* DMSG("patch file is loaded\n"); */

			break;
		}
		case 4: 
			
			break;
		case 5: 
		{
			
			strncpy(sockname, optarg, PATH_MAX);
			DMSG("socket: %s\n", sockname);
			
			break;
		}
		
		case 6:
			usage();
		default:
			break;
		}
	}

// TODO: un-globalize sockname, sockfd, filepath etc.
	if (info_flag > 0) {
		if ((sockfd = connect_to_sandbox(sockname)) < 0) {
			DMSG("error connecting to sandbox server\n");
			return SANDBOX_ERR_RW;
		}
		
		int info = get_info_strings(sockfd, 1);
		if (info != SANDBOX_OK)  {	
			DMSG("error getting build info\n");
		}
		if (sockfd > 0) {
			close(sockfd);
			sockfd = -1;
		}
		
		
	}
	

	if (apply_flag > 0) {

		int ccode;
		
		if ((sockfd = connect_to_sandbox(sockname)) < 0) {
			DMSG("error connecting to sandbox server\n");
			return SANDBOX_ERR_RW;
		}	

		if ((ccode = cmd_apply(sockfd)) < 0)
			DMSG("error applying patch %d\n", ccode);
		close(sockfd);
		return ccode;
		
	}
	
	
	
	if (sockfd > 0)
		close(sockfd);
	
	printf("bye\n");
	return SANDBOX_OK;
	
}
