#define _GNU_SOURCE
#include <link.h>
#include <sys/mman.h>
#include "atomic.h"
#include "sandbox.h"

#define str1(s) #s
#define str(s) str1(s)


extern uint64_t _start, _end;
uint64_t sandbox_cur_rip;

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


struct sandbox_header sh;
struct sandbox_header *sandhead = &sh;
uintptr_t __start = (uintptr_t)&_start;

struct sandbox_header *(*blob_buf)(int) = fill_sandbox;
//#if defined (__X86_64__) || defined (__i386__)
struct sandbox_header *__attribute__((optimize("O0")))fill_sandbox(int c)
{
    uintptr_t sandbox_cur_rip = (uintptr_t)*blob_buf;
    
    sh._start = sandbox_cur_rip; 
    sh._end = sh._start + (PLATFORM_ALLOC_SIZE * PLATFORM_ALLOC_SIZE);
    sh._cursor = sh._start + 0x100;;
    if (c)
        return &sh;
    __asm__ volatile ("mfence\n"
                      ".align 8\n");
    __asm__ volatile (".fill " str(PLATFORM_ALLOC_SIZE) " * " str(PLATFORM_ALLOC_SIZE) ",1,0xc3");
    return &sh;
}
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
        assert(size < (unsigned int)MAX_PATCH_SIZE);
        
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
                uint8_t data[8];
                uint8_t hvabs[8];
                uint8_t temp[8];
                
                memcpy(data, pw->data, 8);
                memcpy(hvabs, (const void * restrict)pw->hvabs, 8);
                memcpy(temp, data, 8);
                
//void __atomic_exchange (type *ptr, type *val, type *ret, int memorder)
                DMSG("preparing to swap tramopolines: hvabs %p, data %p\n", pw->hvabs,
                     pw->data);

                DMSG("saved values: data, %8x; hvabs, %8x; temp, %8x\n",
                     (uint64_t)data[0], (uint64_t)hvabs[0], (uint64_t)temp[0]);

                uint8_t *jmp, *landing;
                
                for(int i = 0; i < 8; i++ ) {
                    jmp = (uint8_t *)pw->hvabs;
                    landing = data;
                    *jmp = *landing;
                    jmp++; landing++;
                    
                }
                
                for(int i = 0; i < 8; i++) {
                    jmp = hvabs;
                    landing = (uint8_t *)pw->data;
                    *landing = *jmp;
                    jmp++; landing++;
                    
                }
                DMSG("swap completed: hvabs %x, data %x\n", *hvabs, *data);
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
    sandhead = fill_sandbox(1);
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
    uint64_t runtime_constant = 0;
    
/****
     Everything about the patch at this time is relative to the the _start symbol.
     "_start is just one symbol we could use, blah blah blah."
     however t _start symbol has been relocated when this program was executed.
     Further, we are placing the new patched code somewhere in the sandbox memory, 
     which we didn't know until now. 

     Here are some variables we will be using to make this 2nd-stage relocation work:

    refabs: a reference point for all other address offsets. We use _start in the 
            elf file and in the patch file. We need to get the current 
           (relocated) address of _start in order to continue with relocations. 
    

  uint64_t hvabs;      Absolute address in HV of the function to be patched

    
    hvabs: the absolute, relocated position of the code to be patched. We don't
           know the absolute address until run time. So in the patch file,
           is relative to refabs before relocation. at run time, we can
           convert this to the relocated absolute address of the code to patch.
          
    relocrel: the newly patched code relative to refabs after relocation.
              blob (new) - _start (relocated) =  (1) in the scratch pad

              relocrel is also necessary to normalize distances in the 
              new code.

     runtime_constant: the difference in refabs before and after relocation.
                       used as a sanity check, may be removed at a later time. 

    relocrel  blob_p - refabs: distance from _start (refabs) to the new code 
                        (landing in the sandbox) at runtime (abs).

 ***/
    /* Blobs are optional */
    if (apply->bloblen) {
        if (!blob_p || !writes_p || !apply || !arg) {
            DMSG("error invalid parameters in read_patch_data2\n");
            return SANDBOX_ERR_INVALID;
        }

        *blob_p = (unsigned char *)get_sandbox_memory(apply->bloblen);
        /* *blob_p is now the landing point */
        
        if (!(*blob_p)) {
            DMSG("error allocating %d bytes memory in read_patch_data2\n",
                 apply->bloblen);
            return SANDBOX_ERR_NOMEM;
        }

        DMSG("read_patch_data2: blob: %p arg: %p len: %d\n", *blob_p,
             arg, apply->bloblen);
        
        /* blob is statically allocated within .text */
        /* Copy blob to hypervisor */
        memcpy(*blob_p, arg, apply->bloblen);
    
        /* Skip over blob */
        arg = (unsigned char *)arg + apply->bloblen;


        DMSG("adjusting refabs, before: %lx\n", apply->refabs);
        runtime_constant = (int64_t)__start - apply->refabs;
        apply->refabs += runtime_constant;
        DMSG("refabs adjusted: %lx\n", apply->refabs);

    }
    relocrel = (uint64_t)(*blob_p) - apply->refabs;
    DMSG("relocrel: %lx (%ld)\n", relocrel, relocrel);
    
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
            DMSG("Normalizing 32-bit offset from blob to _start to the blob\n");
            DMSG("value before write: %lx\n", *(int32_t *)(*blob_p + off));
            *((int32_t *)(*blob_p + off)) -= relocrel;
            DMSG("value after write: %lx\n", *(int32_t *)(*blob_p + off));
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

    /* Verify writes and apply any relocations in writes


   pw->hvabs = resting address of function to be patched, (jmp location)
   pw->data contains the jmp instruction to apply
   pw->dataoff needs the offset within pw->data where to place the jmp distance

   relocrel at this point is the distance of the blob to the 
   reference (_start)
*/
        for (i = 0; i < apply->numwrites; i++) {
            struct xenlp_patch_write *pw = &((*writes_p)[i]);
            char off = pw->dataoff;            
            /* adjust the hvabs to the runtime (after 1st relocation) */
            pw->hvabs += runtime_constant;

            if (pw->hvabs < (uint64_t)__start || pw->hvabs >= (uint64_t)&_end ) {
                printk("invalid hvabs value %lx\n", pw->hvabs);
            }
            
        if (off < 0)
            continue;

        
        /* HV .text -> blob */
        switch (pw->reloctype) {
            case XENLP_RELOC_UINT64:
                if (off > sizeof(pw->data) - sizeof(uint64_t)) {
                    printk("invalid dataoff value %d\n", off);
                    return -EINVAL;
                }
                /* update the jmp distance within the patch write */
                /* relocrel should be the distance between pw->hvabs and blob */
                DMSG("jmp distance within 64-bit patch buf before write: %lx (%ld) \n",                                 *((uint64_t *)(pw->data + off)),
                             *((uint64_t *)(pw->data + off)));
                
                *((uint64_t *)(pw->data + off)) += relocrel;
                
                DMSG("jmp distance within 64-bit patch buf AFTER write: %lx (%dx) \n",
                     *((uint64_t *)(pw->data + off)),
                     *((uint64_t *)(pw->data + off)));
                
                break;
            case XENLP_RELOC_INT32:
                if (off > sizeof(pw->data) - sizeof(int32_t)) {
                    printk("invalid dataoff value %d\n", off);
                    return -EINVAL;
                }
                DMSG("jmp distance within 32-bit patch buf before write: %lx (%d)\n",
                     *((int32_t *)(pw->data + off)),
                     *((int32_t *)(pw->data + off)));

                *((int32_t *)(pw->data + off)) += relocrel;

                DMSG("jmp distance within 32-bit patch buf AFTER write: %lx (%d)\n",
                     *((int32_t *)(pw->data + off)),
                     *((int32_t *)(pw->data + off)));
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

    make_text_writeable(writes, apply.numwrites);
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
