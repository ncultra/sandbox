#define _GNU_SOURCE
#include <link.h>
#include <libelf.h>
#include <sys/mman.h>
#include "sandbox.h"

#define str1(s) #s
#define str(s) str1(s)

/************************************************************
 * The .align instruction has a different syntax on X86_64
 * than it does on PPC64. 
 *
 * On X86_64, the operand to .align is an absolute address.
 * On PP64, the operand is an exponent of base 2.
 * .align 8 on X86 is equal to .align 3 on PPC (2^3 = 8.)
 *
 ************************************************************/
/* TODO: configure option for building with a tiny sandbox. Client applications */
/* can use the library without wasting space in the sandbox */

uint64_t fill = PLATFORM_ALLOC_SIZE;

	__asm__(".text");
	__asm__(".global patch_sandbox_start");
	__asm__(".global patch_sandbox_end");

#if defined (__X86_64__) || defined (__i386__)
	__asm__(".align " str(PLATFORM_CACHE_LINE_SIZE)); // cache line size
#endif

#ifdef  PPC64LE
	__asm__(".align 0x0c");
#endif

	__asm__("patch_sandbox_start:");

#if defined (__X86_64__) || defined (__i386__)
	__asm__("mfence");
	__asm__("jmp patch_sandbox_end");
	__asm__(".text");
	__asm__(".fill " str(PLATFORM_ALLOC_SIZE) " * " str(PLATFORM_ALLOC_SIZE) ",1,0xc3");
// TODO: get rid of this constant, gas doesn't use the cpp 
	__asm__(".align 8");

#endif
#ifdef PPC64LE
	__asm__("b patch_sandbox_end");
	__asm__(".fill 1000 * 1000,1,0x00");
	__asm__(".align 3");

#endif
	__asm__("patch_sandbox_end:");

#if defined (__X86_64__)
	__asm__("retq");
#endif

#if defined (__i386__)
	__asm__("ret");
#endif

#ifdef PPC64LE
	__asm__("blr");
#endif



FILE *log_fd = NULL;
int log_level = 1; /* mirror log to stdout */
int DEBUG = 0;

int set_loglevel(int l) 
{
	int old = log_level;
	log_level = l;
	return old;
}


int set_debug(int db)
{
	int old = DEBUG;
	DEBUG = db;
	printf("debug messages are %s", db > 0 ? "on" : "off" );
	return old;
}



FILE * open_log(void) 
{
	char lpath[0x32];
	snprintf(lpath, 0x32, "sand_log_%d", getpid());
	log_fd = fopen(lpath, "a");
	return log_fd;
}


void DMSG(char *fmt, ...)
{
	if (DEBUG) {
		va_list va;
		va_start(va, fmt);
		vfprintf(stderr, fmt, va);
		va_end(va);
		
	}
}


void LMSG(char *fmt, ...)
{
	va_list va;
	if (log_fd == NULL) {
		DMSG("opening log file\n");		
		log_fd = open_log();
		if (log_fd == NULL) {
			DMSG("could not open log file\n");	
			perror(NULL);
			return;
		}
	}
	if (log_level > 0) {
		va_list vb;
		va_copy(vb, va);
		va_start(vb, fmt);
		vfprintf(stdout, fmt, vb);
		va_end(vb);
	}
	
	va_start(va, fmt);
	vfprintf(log_fd, fmt, va);
	va_end(va);
	
}




/* TODO: merge with sandbox struct patch */

/* this is the 'new'patch struct */
LIST_HEAD(patch_list);

/* Linked list of applied patches */
LIST_HEAD(applied_list);

uint8_t *patch_cursor = NULL;


uint64_t get_sandbox_start(void)
{
	return  (uint64_t)( &patch_sandbox_start);
}

uint64_t get_sandbox_end(void)
{
	return (uint64_t)&patch_sandbox_end;
	
}

static void *get_sandbox_memory(uint32_t size)
{
	uint8_t *p = NULL;
	
	assert(get_sandbox_free() > size);
        assert(size < MAX_PATCH_SIZE);
        
	patch_cursor = (uint8_t *)ALIGN_POINTER((uintptr_t)patch_cursor,
						PLATFORM_CACHE_LINE_SIZE);
	p = patch_cursor;
	
	/* paranoid, be certain there are no code fragments wondering around 
	   in the sandbox. */
	memset(p, size, sizeof(uint8_t));	
	patch_cursor += size;
	patch_cursor = (uint8_t *)ALIGN_POINTER((uintptr_t)patch_cursor,
						PLATFORM_CACHE_LINE_SIZE);
	return p;
}

void bin2hex(unsigned char *bin, size_t binlen, char *buf,
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
void swap_trampolines(struct xenlp_patch_write *writes, uint32_t numwrites)
{
	
	int i;
	
	for (i = 0; i < numwrites; i++) {
		struct xenlp_patch_write *pw = &writes[i];

	    atomic_xchg((uint64_t *)&pw->hvabs,
			(uint64_t *)&pw->data);
	    
	
	}
}


/* unlike the xen kernel, there is a good chance that the .text is not writeable. 
 * So, make the text page that will host the trampoline writeable.
 */
static void make_text_writeable(struct xenlp_patch_write *writes,
				uint32_t numwrites)
{
	int i;
	for (i = 0; i < numwrites; i++) {
		struct xenlp_patch_write *pw = &writes[i];
		uint64_t p = (uint64_t)pw->hvabs;
		p &= PLATFORM_PAGE_MASK;
		if (mprotect((void *)p , PLATFORM_PAGE_SIZE,
			     PROT_READ|PROT_EXEC|PROT_WRITE)){			
			perror("err: ");

		}	
	}
}



/* server-side apply function */
/* corresponds to do_lp_apply on the raxl side */
int xenlp_apply(void *arg)
{
	struct xenlp_apply *apply = (struct xenlp_apply *)arg;
	unsigned char *blob = NULL;
	struct xenlp_patch_write *writes;
	size_t i;
	struct applied_patch *patch;
	int32_t relocrel = 0;
	char sha1[41];
	unsigned char *p;
	

    
	/* Skip over struct xenlp_apply */
	p = (unsigned char *)arg + sizeof(struct xenlp_apply);

	/* Do some initial sanity checking */
	if (apply->bloblen > MAX_PATCH_SIZE) {
		LMSG("live patch size %u is too large\n", apply->bloblen);
		return -EINVAL;
	}

	DMSG("live patch size: %u\n", apply->bloblen);

	
	if (apply->numwrites == 0) {
		LMSG("need at least one patch\n");
		return -EINVAL;
	}
	DMSG("number of writes: %d \n", apply->numwrites);
	
	
	patch = calloc(1, sizeof(struct applied_patch));
	if (!patch)
		return SANDBOX_ERR_NOMEM;

	/* FIXME: Memory allocated for patch can leak in case of error */

	/* Blobs are optional */

	/* use sandbox memory */
	blob = get_sandbox_memory(apply->bloblen);
	if (!blob)
		return SANDBOX_ERR_NOMEM;
    
	/* FIXME: Memory allocated for blob can leak in case of error */
    
	/* Copy blob to hypervisor was */
	memcpy(blob, p, apply->bloblen);
    
	/* Skip over blob */
	p += apply->bloblen;
    
	/* Calculate offset of relocations */
	relocrel = (uint64_t)blob - apply->refabs;



/* Read relocs */

	DMSG("number of relocs: %d\n", apply->numrelocs);
	
	if (apply->numrelocs) {
		uint32_t *relocs;
	
		relocs = calloc(apply->numrelocs, sizeof(uint32_t));

		if (!relocs)
			return SANDBOX_ERR_NOMEM;

		/* was copy from guest */

		p += (apply->numrelocs * sizeof(relocs[0]));

		for (i = 0; i < apply->numrelocs; i++) {
			uint32_t off = relocs[i];
			if (off > apply->bloblen - sizeof(int32_t)) {
				DMSG("invalid off value %d\n", off);
				return SANDBOX_ERR_PARSE;
			}

			/* blob -> HV .text */
			*((int32_t *)(blob + off)) -= relocrel;
		}

		free(relocs);
	}

	/* Read writes */
	writes = calloc(apply->numwrites, sizeof(struct xenlp_patch_write));
	if (!writes)
		return SANDBOX_ERR_NOMEM;

	memcpy(writes, p, apply->numwrites * sizeof(writes[0]));
    
	/* Move over all of the writes */
	p += (apply->numwrites * sizeof(writes[0]));

	/* Verify writes and apply any relocations in writes */
	for (i = 0; i < apply->numwrites; i++) {
		struct xenlp_patch_write *pw = &writes[i];
		char off = pw->dataoff;
/* removed the validation test that used to be here because we don't 
 * need it (we have a sandbox) */
		if (off < 0)
			continue;

		/* HV .text -> blob */
		/* TODO: confirm only need the 32-bit variant */
		switch (pw->reloctype) {
		case XENLP_RELOC_UINT64:
			DMSG("write is a 64-bit reloc\n");
			if (off > sizeof(pw->data) - sizeof(uint64_t)) {
				DMSG("invalid dataoff value %d\n", off);
				return SANDBOX_ERR_PARSE;
			}

			*((uint64_t *)(pw->data + off)) += relocrel;
			break;
		case XENLP_RELOC_INT32:
			DMSG("write is a 32-bit reloc\n");
			if (off > sizeof(pw->data) - sizeof(int32_t)) {
				DMSG("invalid dataoff value %d\n", off);
				return SANDBOX_ERR_PARSE;
			}

			*((int32_t *)(pw->data + off)) += relocrel;
			break;
		default:
			DMSG("unknown reloctype value %u\n", pw->reloctype);
			return SANDBOX_ERR_PARSE;
		}
	}


	make_text_writeable(writes, apply->numwrites);
    
	/* Nothing should be possible to fail now, so do all of the writes */
	swap_trampolines(writes, apply->numwrites);
	/* Record applied patch */
	patch->blob = blob;
	memcpy(patch->sha1, apply->sha1, sizeof(patch->sha1));
	DMSG("incoming patch sha1:\n");
	dump_sandbox(patch->sha1, 20);
	
	patch->numwrites = apply->numwrites;
	patch->writes = writes;
	INIT_LIST_HEAD(&patch->l);

	list_add(&patch->l, &applied_list);
	bin2hex(apply->sha1, sizeof(apply->sha1), sha1, sizeof(sha1));
	LMSG("successfully applied patch %s\n", sha1);

	return 0;
}

uint8_t *make_sandbox_writeable(void) 
{

	
	uint64_t p = (uint64_t)&patch_sandbox_start;
	
	DMSG ("sandbox start before alignment\n %016lx\n",(uint64_t)&patch_sandbox_start);
	p &= PLATFORM_PAGE_MASK;
	DMSG("page mask: %016lx\n", (uint64_t)PLATFORM_PAGE_MASK);
	
	DMSG ("sandbox start %016lx\n", (uint64_t)&patch_sandbox_start);
	DMSG ("page size: %016lx\n", (uint64_t)PLATFORM_PAGE_SIZE);
	printf("page-aligned address: %016lx\n", p);
	
	if (mprotect((void *)p, SANDBOX_ALLOC_SIZE,
		     PROT_READ|PROT_EXEC|PROT_WRITE)) {
		DMSG("memprotect failed, %i\n", errno);
		perror("err: ");
		
	}
	return (uint8_t *)p;
}


void init_sandbox(void)
{
	make_sandbox_writeable(); 
	patch_cursor = (uint8_t *)&patch_sandbox_start;
	uint64_t p  = (uint64_t)&applied_list;
	p &= PLATFORM_PAGE_MASK;
	if (mprotect((void *)p, PLATFORM_PAGE_SIZE,
		     PROT_READ|PROT_EXEC|PROT_WRITE))
		perror("err: ");
	
}

void dump_sandbox(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	if (DEBUG < 1)
		return;
	
	ascii[16] = '\0';
	printf ("\n");
	printf ("%08lx\t", (unsigned long) (unsigned char *)data);
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0 && i + 1 < size) {
				printf("|  %s \n%08lx\t", ascii, (unsigned long)(((unsigned char *)data) + i));
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("\n");
				
			}
			
		}
	}
}
