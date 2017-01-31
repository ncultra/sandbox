#define _GNU_SOURCE
#include <link.h>
#include <sys/mman.h>
#include "atomic.h"
#include "sandbox.h"

#define str1(s) #s
#define str(s) str1(s)


extern uintptr_t _start, _end;


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

#if defined (__X86_64__) || defined (__i386__)
	__asm__(".align " str(PLATFORM_CACHE_LINE_SIZE));
#endif

#ifdef  PPC64LE
	__asm__(".align 0x0c");
#endif

/* sandbox is 4MB,  can make it larger or smaller if needed. */


#ifdef PPC64LE
	__asm__("b patch_sandbox_end");
	__asm__(".fill 1000 * 1000,1,0x00");
	__asm__(".align 3");

#endif

#if defined (__X86_64__)
	__asm__("retq");
#endif

#if defined (__i386__)
	__asm__("ret");
#endif

#ifdef PPC64LE
	__asm__("blr");
#endif


uintptr_t ALIGN_POINTER(uintptr_t p, uintptr_t offset)
 { 
 	if (! p % offset)
 		return p;
	p += (offset - 1);
 	p &= ~(offset - 1);
 	return p;
}

struct sandbox_header *sandhead = NULL;


//#if defined (__X86_64__) || defined (__i386__)

#pragma GCC push_options
#pragma GCC optimize ("O0")

struct sandbox_header *fill_sandbox(void)
{
    static struct sandbox_header sh;
/*  sandbox is 10k */
    sh._start = (uintptr_t)__builtin_frame_address(0);
    sh._end = sh._start + (PLATFORM_ALLOC_SIZE * PLATFORM_ALLOC_SIZE);
    sh._cursor = (uintptr_t)__builtin_frame_address(0);

    __asm__("mfence");
    __asm__(".align 8");
    __asm__(".fill " str(PLATFORM_ALLOC_SIZE) " * " str(PLATFORM_ALLOC_SIZE) ",1,0xc3");
    return &sh;;
}
#pragma GCC pop_options
//#endif
uintptr_t update_patch_cursor(uintptr_t offset)
{
    assert(sandhead != NULL);
    return sandhead->_cursor += offset;
}


ptrdiff_t get_sandbox_free(void)
{
    assert(sandhead != NULL);
    return (ptrdiff_t) sandhead->_end - sandhead->_cursor;
}

FILE *log_fd = NULL;
int log_level = 1; /* mirror log to stdout */
int DEBUG = 1;

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
	printf("debug messages are %s\n", db > 0 ? "on" : "off" );
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

extern void va_copy(va_list dest, va_list src);
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

/* Linked list of applied patches */
/* TODO: remove lp_patch_head2, we don't need it */
LIST_HEAD(lp_patch_head2);
LIST_HEAD(lp_patch_head3);

uintptr_t get_sandbox_start(void)
{
	return  sandhead->_start;
}

uintptr_t get_sandbox_end(void)
{
	return sandhead->_end;
	
}


static uintptr_t get_sandbox_memory(ptrdiff_t size)
{
	uintptr_t p = 0L;

        assert(sandhead != NULL);
	assert(get_sandbox_free() > size);
        assert(size < MAX_PATCH_SIZE);

        
	p = (uintptr_t)ALIGN_POINTER(sandhead->_cursor,
                                     PLATFORM_CACHE_LINE_SIZE);
	
	/* be certain there are no code fragments wondering around 
	   in the sandbox. */
	memset((void *)p, 0xc3, size);	
	sandhead->_cursor += size;
	sandhead->_cursor = (uintptr_t) ALIGN_POINTER(sandhead->_cursor,
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

static unsigned int __attribute__((used))
hex_to_int(const char *ptr)
{
    unsigned int value = 0;
    char ch = *ptr;
    int i;

    while (ch == ' ' || ch == '\t')
        ch = *(++ptr);

    for (i = 0; i < 4; i++) {

        if (ch >= '0' && ch <= '9')
            value = (value << 4) + (ch - '0');
        else if (ch >= 'A' && ch <= 'F')
            value = (value << 4) + (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f')
            value = (value << 4) + (ch - 'a' + 10);
        else
            return value;
        ch = *(++ptr);
    }
    return value;
}

void hex2bin(char *buf, size_t buflen, unsigned char *bin, size_t binlen)
{

    int count = 0, sha_count = 0;
    char *p = buf;
    
    while(count <= buflen && sha_count <= binlen) {
        bin[sha_count] = htoi(*(p + count));
        count += 4;	
        sha_count++;
    }	
}

void swap_trampolines(struct xenlp_patch_write *writes, uint32_t numwrites)
{
	
	int i;
	
	for (i = 0; i < numwrites; i++) {
		struct xenlp_patch_write *pw = &writes[i];

	    atomic_xchg((uintptr_t *)&pw->hvabs,
			(uintptr_t *)&pw->data);
        }
}


/* unlike the xen kernel, there is a good chance that the .text is not writeable. 
 * So, make the text page that will host the trampoline writeable.
 */
void make_text_writeable(struct xenlp_patch_write *writes,
				uint32_t numwrites)
{
	int i;
	for (i = 0; i < numwrites; i++) {
		struct xenlp_patch_write *pw = &writes[i];
		uintptr_t p = (uintptr_t)pw->hvabs;
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
	struct xenlp_apply3 *apply = (struct xenlp_apply3 *)arg;
	uintptr_t blob = 0L;
	struct xenlp_patch_write *writes;
	size_t i;
	struct applied_patch3 *patch;
	ptrdiff_t relocrel = 0;
	char sha1[42];
	ptrdiff_t p;
	

    
	/* Skip over struct xenlp_apply */
	p = (ptrdiff_t) arg + sizeof(struct xenlp_apply3);

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
	
	
	patch = calloc(1, sizeof(struct applied_patch3));
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
	memcpy((void *)blob, (void *)p, apply->bloblen);
        
       /* Skip over blob */
	p += apply->bloblen;
    
	/* Calculate offset of relocations */
	relocrel = (ptrdiff_t) blob - apply->refabs;



/* Read relocs */

	DMSG("number of relocs: %d\n", apply->numrelocs);
	
	if (apply->numrelocs) {
		uintptr_t relocs;
	
		relocs = (uintptr_t) calloc(apply->numrelocs, sizeof(uintptr_t));

		if (!relocs)
			return SANDBOX_ERR_NOMEM;

		/* was copy from guest */

		p += (apply->numrelocs * sizeof(uintptr_t));

		for (i = 0; i < apply->numrelocs; i++) {
			ptrdiff_t off = relocs + i;
			if (off > apply->bloblen - sizeof(uintptr_t)) {
				DMSG("invalid off value %d\n", off);
				return SANDBOX_ERR_PARSE;
			}

			/* blob -> HV .text */

                        *((uintptr_t *)(blob + off)) -= relocrel;
		}

		free((void *)relocs);
	}

	/* Read writes */
	writes = calloc(apply->numwrites, sizeof(struct xenlp_patch_write));
	if (!writes)
		return SANDBOX_ERR_NOMEM;

	memcpy(writes, (void *)p, apply->numwrites * sizeof(writes[0]));
    
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

/* up to here is moved into read_patch_data2 */
	make_text_writeable(writes, apply->numwrites);
    
	/* Nothing should be possible to fail now, so do all of the writes */
	swap_trampolines(writes, apply->numwrites);
	/* Record applied patch */
	patch->blob = (void *)blob;
	memcpy(patch->sha1, apply->sha1, sizeof(patch->sha1));
	DMSG("incoming patch sha1:\n");
	dump_sandbox(patch->sha1, 20);
        patch->numwrites = apply->numwrites;
        patch->writes = writes;
        INIT_LIST_HEAD(&patch->l);
	
	list_add(&patch->l, &lp_patch_head2);
        memset(sha1, 0x00, sizeof(sha1));
	bin2hex(apply->sha1, sizeof(apply->sha1), sha1, sizeof(sha1) - 1);
	LMSG("successfully applied patch %s\n", sha1);

	return 0;
}

uintptr_t make_sandbox_writeable(void) 
{

	
	uintptr_t p = (uintptr_t)sandhead->_start;
	
	DMSG ("sandbox start before alignment\n %016lx\n", sandhead->_start);
	p &= PLATFORM_PAGE_MASK;
	DMSG("page mask: %016lx\n", (uintptr_t)PLATFORM_PAGE_MASK);
	
	DMSG ("sandbox start %016lx\n", (uintptr_t) sandhead->_start);
	DMSG ("page size: %016lx\n", (uintptr_t)PLATFORM_PAGE_SIZE);
	printf("page-aligned address: %p\n", (void *)p);
	
	if (mprotect((void *)p, SANDBOX_ALLOC_SIZE,
		     PROT_READ|PROT_EXEC|PROT_WRITE)) {
		DMSG("memprotect failed, %i\n", errno);
		perror("err: ");
		
	}
	return p;
}

void init_sandbox(void)
{
    sandhead = fill_sandbox();
    make_sandbox_writeable(); 
    uintptr_t p  = (uintptr_t) &lp_patch_head3;
    p &= PLATFORM_PAGE_MASK;
    if (
        mprotect((void *)p, PLATFORM_PAGE_SIZE,
                 PROT_READ|PROT_EXEC|PROT_WRITE)) {    
        perror("err: ");
    }        
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



/*******************************************
 * COMPATIBILITY code from xen-livepatch
 *
 ******************************************/

/* arg points to the apply buffer just past the xenlp_apply struct */
/* apply points to the xenlp_apply struct (also beginning of the original buffer */
/* blob_p and writes_p both point to stack variables in the caller's stack */
int read_patch_data2(XEN_GUEST_HANDLE(void) *arg, struct xenlp_apply3 *apply,
                            unsigned char **blob_p, struct xenlp_patch_write **writes_p)
{
    size_t i;
    int32_t relocrel = 0;
    
    /* Blobs are optional */if (apply->bloblen) {
        if (!blob_p || !writes_p || !apply || !arg) {
            DMSG("error invalid parameters in read_patch_data2\n");
            return SANDBOX_ERR_INVALID;
        }
        
        *blob_p = aligned_zalloc(64, apply->bloblen);

        if (!(*blob_p)) {
            DMSG("error allocating %d bytes memory in read_patch_data2\n",
                 apply->bloblen);
            return SANDBOX_ERR_NOMEM;
        }

        DMSG("read_patch_data2: blob: %p arg: %p len: %d\n", *blob_p,
             arg, apply->bloblen);
        
        /* FIXME: Memory allocated for blob can leak in case of error */
        /* Copy blob to hypervisor */
        memcpy(*blob_p, arg, apply->bloblen);
    
        /* Skip over blob */
        arg = (unsigned char *)arg + apply->bloblen;

        /* Calculate offset of relocations */
        relocrel = (uint64_t)(uintptr_t)(*blob_p) - apply->refabs;
    }

    /* Read relocs */
    if (apply->numrelocs) {
        uint32_t *relocs;

        relocs = xzalloc_array(uint32_t, apply->numrelocs);
        if (!relocs) {
            DMSG("error allocating %d bytes in read_patch_data2\n",
                 apply->numrelocs * sizeof(uint32_t));
            return SANDBOX_ERR_NOMEM;
        }
        
        memcpy(relocs, arg, apply->numrelocs * sizeof(relocs[0]));
        arg = (unsigned char *)arg + (apply->numrelocs * sizeof(relocs[0]));

        for (i = 0; i < apply->numrelocs; i++) {
            uint32_t off = relocs[i];
            if (off > apply->bloblen - sizeof(int32_t)) {
                printk("invalid off value %d\n", off);
                return -EINVAL;
            }

            /* blob -> HV .text  - adjust absolute offsets to this process mem */
            *((int32_t *)(*blob_p + off)) -= relocrel;
        }
        xfree(relocs);
    }

    /* Read writes */
    *writes_p = xzalloc_array(struct xenlp_patch_write, apply->numwrites);
    if (!(*writes_p)) {
        DMSG("error allocating %d bytes in read_patch_data2\n",
             apply->numwrites * sizeof(struct xenlp_patch_write));
        return SANDBOX_ERR_NOMEM;
    }
    
    memcpy(*writes_p, arg, apply->numwrites * sizeof(struct xenlp_patch_write));
    
    /* Move over all of the writes */
    arg = (unsigned char *)arg + (apply->numwrites * sizeof((*writes_p)[0]));

    /* Verify writes and apply any relocations in writes */
    for (i = 0; i < apply->numwrites; i++) {
        struct xenlp_patch_write *pw = &((*writes_p)[i]);
        char off = pw->dataoff;

        /*
        if (pw->hvabs < (uint64_t)_start ||
            pw->hvabs >= (uint64_t)_fini {
            printk("invalid hvabs value %lx\n", pw->hvabs);
        }
        */
        if (off < 0)
            continue;

        
        /* HV .text -> blob */
        switch (pw->reloctype) {
            case XENLP_RELOC_UINT64:
                if (off > sizeof(pw->data) - sizeof(uint64_t)) {
                    printk("invalid dataoff value %d\n", off);
                    return -EINVAL;
                }

                *((uint64_t *)(pw->data + off)) += relocrel;
                break;
            case XENLP_RELOC_INT32:
                if (off > sizeof(pw->data) - sizeof(int32_t)) {
                    printk("invalid dataoff value %d\n", off);
                    return -EINVAL;
                }

                *((int32_t *)(pw->data + off)) += relocrel;
                break;
            default:
                
                printk("unknown reloctype value %u\n", pw->reloctype);
                return -EINVAL;
        }
    }
    return SANDBOX_OK;
}

int xenlp_apply3(void *arg)
{
    struct xenlp_apply3 apply;
    unsigned char *blob = NULL;
    struct xenlp_patch_write *writes;
    struct applied_patch3 *patch;
    char sha1[41];
    int res;

    memcpy(&apply, arg, sizeof(struct xenlp_apply3)); 
    /* FIXME: Manipulating arg.p seems a bit ugly */

    /* Skip over struct xenlp_apply */
    arg = (unsigned char *)arg + sizeof(struct xenlp_apply3);
/* Do some initial sanity checking */
    if (apply.bloblen > MAX_PATCH_SIZE) {
        printk("live patch size %u is too large\n", apply.bloblen);
        return SANDBOX_ERR_INVALID;
    }

    if (apply.numwrites == 0) {
        DMSG("need at least one patch\n");
        return SANDBOX_ERR_INVALID;
    }

    patch = xzalloc(struct applied_patch3);
    if (!patch) {
        DMSG("unable to allocate %d bytes in xenlp_apply3\n",
             sizeof(struct xenlp_apply3));
        return SANDBOX_ERR_NOMEM;
    }
    /* FIXME: Memory allocated for patch can leak in case of error */

    res = read_patch_data2(arg, (struct xenlp_apply3 *)&apply, &blob, &writes);
    if (res < 0) {
        DMSG("fault %d reading patch data\n", res);
        return res;
    }
    
    /* Read dependencies */
    patch->numdeps = apply.numdeps;
    DMSG("numdeps: %d\n", apply.numdeps);
    if (apply.numdeps > 0) {
        patch->deps = xzalloc_array(struct xenlp_hash, apply.numdeps);
        if (!patch->deps) {
            DMSG("error allocating memory for patch dependencies\n");
            return SANDBOX_ERR_NOMEM;
        }
        
        if (memcpy(patch->deps, arg, apply.numdeps * sizeof(struct xenlp_hash))) {
            DMSG("fault copying memory in xenlp_apply3\n"); 
            return SANDBOX_ERR_INVALID;
        }
        
        arg = (unsigned char *)arg + (apply.numdeps * sizeof(struct xenlp_hash));
    }

    /* Read tags */
    patch->tags[0] = 0;
    DMSG("taglen: %d\n", apply.taglen);
    if (apply.taglen > 0 && apply.taglen <= MAX_TAGS_LEN) {
        memcpy(patch->tags, arg, apply.taglen);
        patch->tags[apply.taglen] = '\0';
        arg = (unsigned char *)arg + (apply.taglen * sizeof(char));
        DMSG("tags: %s\n", patch->tags);
    }

    /* Nothing should be possible to fail now, so do all of the writes */
    swap_trampolines(writes, apply.numwrites);

    /* Record applied patch */
    patch->blob = blob;
    memcpy(patch->sha1, apply.sha1, sizeof(patch->sha1));
    patch->numwrites = apply.numwrites;
    patch->writes = writes;

    list_add(&patch->l, &lp_patch_head3);
   
    bin2hex(apply.sha1, sizeof(apply.sha1), sha1, sizeof(sha1));
    printk("successfully applied patch %s\n", sha1);

    return 0;
}

int has_dependent_patches(struct applied_patch3 *patch)
{
    /* Starting from current patch, looking down the linked list
     * Find if any later patches depend on this one */
    struct applied_patch3 *ap = list_next_entry(patch, l);
    while (ap && ap != list_first_entry(&lp_patch_head3, struct applied_patch3, l)) {
        size_t i;
        for (i = 0; i < ap->numdeps; i++) {
            struct xenlp_hash *dep = &ap->deps[i];
            if (memcmp(dep->sha1, patch->sha1, sizeof(patch->sha1)) == 0)
                return 1;
        }
        ap = list_next_entry(ap, l);
    }
    return 0;
}

int xenlp_undo3(XEN_GUEST_HANDLE(void *) arg)
{
    struct xenlp_hash hash;
    struct applied_patch3 *ap;

    memcpy(&hash, arg, sizeof(struct xenlp_hash));
    

    list_for_each_entry(ap, &lp_patch_head3, l) {
        
        if (memcmp(ap->sha1, hash.sha1, sizeof(hash.sha1)) == 0) {
            if (has_dependent_patches(ap) || ap->numwrites == 0)
                return -ENXIO;
            swap_trampolines(ap->writes, ap->numwrites);
            list_del(&ap->l);
            
            xfree(ap->writes);
            xfree(ap->deps);
            xfree(ap);
            return 0;
        }    
    }
    return -ENOENT;
}
