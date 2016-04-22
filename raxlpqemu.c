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

#include "util.h"

#include "sandbox.h"

#define XSPATCH_COOKIE	"XSPATCH2"

static int info_flag, list_flag, apply_flag, remove_flag;
static char filepath[PATH_MAX];
static char patch_basename[PATH_MAX];

static char sockname[PATH_MAX];
static int sockfd;

#define COUNT_INFO_STRINGS 6

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

static void bin2hex(unsigned char *, size_t, char *, size_t);



/* return: < 0 for error; zero if patch applied; one if patch not applied */
/* if sha1 is NULL print all applied patches */
int find_patch(int fd, uint8_t sha1[20])
{
	uint32_t *count, i = 0, ccode = SANDBOX_MSG_APPLY;;
	struct list_response *response;
	
	/* return buffer format:*/
        /* uint32_t count;
         * struct list_response[count];
	 * buffer needs to be freed by caller 
	*/
	count = (uint32_t *)sandbox_list_patches(fd);
	if (count == NULL) {
		DMSG("error getting the list of applied patches\n");
		return SANDBOX_ERR_PARSE;
	} 
	if (*count == 0)
		goto exit;
	
	LMSG("%d applied patches...\n", *count);
	
	response = (struct list_response *) count + sizeof(uint32_t);
	for (i = 0; i < *count; i++) {
		if (sha1 == NULL) {
			char sha1str[41];
			bin2hex(response[i].sha1, sizeof(response[i].sha1),
				sha1str, sizeof(sha1str));
			LMSG("%s\n", sha1str);
		} else if (memcmp(sha1, response[i].sha1, 20) == 0) {
			goto exit;
		}
	}
	
	ccode = SANDBOX_MSG_APPLY;
exit:
	free(count);
	return ccode;
}

int list_patches(int fd)
{
	find_patch(fd, 0L);
	return SANDBOX_OK;
}

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
            DMSG("error: not a valid sha1 string: %s\n", string);
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
	    DMSG("error: missing .raxlpxs extension: filename must be of form <sha1>.raxlpxs\n");
        return -1;
    }

    /* Make sure filename length is 48: 40 (<sha1>) + 8 ('.raxlpxs') */
    if (strlen(filename) != 48) {
        DMSG("error: filename must be of form <sha1>.raxlpxs\n");
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



/* client-side counterpart to xenlp_apply */
int do_lp_apply(int fd, void *buf, size_t buflen)
{
// fill buffer, write it to the socket 
	if (send_rr_buf(fd,
			SANDBOX_MSG_APPLY,
			buflen,
			buf,
			SANDBOX_LAST_ARG) == SANDBOX_OK) {

		void *buf;
		uint16_t version = 1, id = SANDBOX_MSG_APPLYRSP;
		uint32_t len = 0;
		read_sandbox_message_header(fd, &version, &id, &len, &buf);
		
	}
	
	return SANDBOX_OK;
}

int load_patch_file(int fd, char *filename, struct xpatch *patch);
static inline char *get_qemu_version(void);
static inline char *get_qemu_date(void);

size_t fill_patch_buf(unsigned char *buf, struct xpatch *patch,
                      uint32_t numwrites, struct xenlp_patch_write *writes)
{
    unsigned char *ptr = buf;
    struct xenlp_apply apply = {
        bloblen: patch->bloblen,

        numrelocs: patch->numrelocs,
        numwrites: numwrites,

        refabs: patch->refabs,
    };

    size_t buflen = sizeof(apply) + patch->bloblen +
                    (patch->numrelocs * sizeof(patch->relocs[0])) +
                    (numwrites * sizeof(writes[0]));

    if (buf == NULL)
        return buflen;

    memcpy(apply.sha1, patch->sha1, sizeof(apply.sha1));

#define ADR(d, s)	do { memcpy(ptr, d, s); ptr += s; } while (0)
#define AD(d)		ADR(&d, sizeof(d))
#define ADA(d, n)	ADR(d, sizeof(d[0]) * n)

    AD(apply);				/* struct xenlp_apply */
    if (patch->bloblen > 0)
        ADR(patch->blob, patch->bloblen);	/* blob */
    if (patch->numrelocs > 0)
        ADA(patch->relocs, patch->numrelocs);	/* relocs */
    if (numwrites > 0)
        ADA(writes, numwrites);		/* writes */

    return (ptr - buf);
}


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

 
    LMSG("  QEMU Version: %s\n", qemu_version);
    LMSG("  QEMU Compile Date: %s\n", qemu_compile_date);

    LMSG("\n");
    LMSG("Patch Applies To:\n");
    LMSG("  QEMU Version: %s\n", patch.xenversion);
    LMSG("  QEMU  Compile Date: %s\n", patch.xencompiledate);
    LMSG("\n");


    if (strncmp(qemu_version, patch.xenversion, INFO_STRING_LEN) != 0 ||
	strncmp(qemu_compile_date, patch.xencompiledate, INFO_STRING_LEN) != 0) {
	    DMSG("error: patch does not match QEMU build\n");
	    return SANDBOX_ERR_BAD_VER;
    }
    
    /* Do a list first and make sure patch isn't already applied yet */
    if (find_patch(fd, patch.sha1) == SANDBOX_OK) {
        LMSG("Patch is already applied, skipping\n");
        return SANDBOX_OK;
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

        LMSG("Patching function %s @ %llx\n", func->funcname,
	       (long long unsigned int)func->oldabs);
    }

    size_t buflen = fill_patch_buf(NULL, &patch, numwrites, writes);
    unsigned char *buf = _zalloc(buflen);
    buflen = fill_patch_buf(buf, &patch, numwrites, writes);

    int ret = do_lp_apply(fd, buf, buflen);
    if (ret < 0) {
        DMSG("failed to patch hypervisor: %m\n");
        return -1;
    }

    char sha1str[41];
    bin2hex(patch.sha1, sizeof(patch.sha1), sha1str, sizeof(sha1str));
    LMSG("\nSuccessfully applied patch %s\n", sha1str);
    return 0;
}



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
        DMSG("%s: hash mismatch\n", filename);
        bin2hex(hash, sizeof(hash), hex, sizeof(hex));
        DMSG("  calculated %s\n", hex);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);

    char signature[8];
    if (_read(filename, fd, signature, sizeof(signature)) < 0)
        return -1;

    if (memcmp(signature, XSPATCH_COOKIE, sizeof(signature))) {
        DMSG("%s: invalid signature\n", filename);
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
			LMSG("%s\n", info_strings[index]);
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


static inline void get_options(int argc, char **argv)
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
		c = getopt_long_only(argc, argv, "ila:r:s:h", long_options, &option_index);
		if (c == -1) {
			break;
		}
		
	restart_long:
		switch (option_index) {
		case 0:
			switch (c) {
			case  'i':
				option_index = 1;
				info_flag = 1;
				goto restart_long;
			case 'l':
				option_index = 2;
				list_flag = 1;
				goto restart_long;
			case 'a' :
				option_index = 3;
				apply_flag = 1;
				goto restart_long;
			case 'r':
				option_index = 4;
				remove_flag = 1;
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
			info_flag = 1;
			DMSG("selected option %s\n", long_options[option_index].name);
			break;
			
		case 2:
			break;
			
		case 3:
		{
						
			strncpy(filepath, optarg, sizeof(filepath) - 1);
			LMSG("patch file: %s\n", filepath);
			break;
		}
		case 4: 
			
			break;
		case 5: 
		{
			
			strncpy(sockname, optarg, PATH_MAX);
			LMSG("socket: %s\n", sockname);
			
			break;
		}
		
		case 6:
			usage();
		default:
			break;
		}
	}

}

	
int main(int argc, char **argv)
{
	

	get_options(argc, argv);
	
	/* we don't run these functions within the option switch because */
	/* we reply on having the sockname set, which can happen after other options */
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
	
	LMSG("bye\n");
	return SANDBOX_OK;
	
}
