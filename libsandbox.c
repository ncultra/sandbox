#include <sys/mman.h>
#include "atomic.h"
#include "sandbox.h"
#include "pmparser.h"

/* #define str1(s) #s
   #define str(s) str1(s)
*/
extern uintptr_t _start, _end;

/* head of list of applied patches */
struct lph lp_patch_head;

uintptr_t
ALIGN_POINTER (uintptr_t p, uintptr_t offset)
{
  if (!p % offset)
    return p;
  p += (offset - 1);
  p &= ~(offset - 1);
  return p;
}

/* find_sandbox_start(backing) 
 * requirements for maps containing live patches:
 * 1) must be less than 2^32 from the function being patched
 * 2) must not overlap qemu maps, including heap
 *
 * on Linux this equates to mapping the sandbox beginning
 * after the heap.
 * 
 * the map_patch_map function will check to ensure a map
 * is within the correct range, and will leave a hole for
 * heap expansion.
*/
uintptr_t
find_sandbox_start (char *backing)
{
  procmaps_struct *iter = NULL;
  uintptr_t sandbox_start = 0L;
  procmaps_struct *maps = pmparser_parse (getpid ());

  if (maps == NULL)
    {
      DMSG ("unable to parse /proc/maps");
      return sandbox_start;
    }

  while ((iter = pmparser_next ()) != NULL)
    {
      /* look for heap mapping */
      if (iter->pathname)
	{
	  char *pos = strstr (iter->pathname, "[heap]");
	  if (pos != NULL && strlen (pos) > 0)
	    {
	      /* grab the ending address, add a hole, 
	       * return the result */
	      sandbox_start = (uintptr_t) iter->addr_end + 0x100000;
	      goto out;
	    }
	}
    }
out:
  if (maps != NULL)
    {
      pmparser_free (maps);
    }
  return sandbox_start;
}


/* int map_patch_map
 * in/out: struct patch_map pm 
 * pm->size in/out
 * pm->addr out only
 *
 * return: SANDBOX_OK upon success, SANDBOX_ERR_* otherwise
 * pm->size is invalid when returning an error
 *
 * map_patch_map will start mapping at the return value
 * of find_sandbox_start("heap").
 * 
 * It will map a range of memory for each live patch,
 * sequentially, until the next address for a map is
 * going to start at and address greater than 
 * _start + (2^32 - 1)
*/

int
map_patch_map (struct patch_map *pm)
{
  static struct patch_map last;
  static uint64_t ultimate_limit;
  struct patch_map next;

/* ultimate_limit is the highest address we can safely allocate for a 
 * 32-bit near jump and relocate
 */
  if (ultimate_limit == 0)
    {
      ultimate_limit = (uint64_t) (&_start + 0xffffffff) & PAGE_MASK;
    }

  if (last.addr == 0L)
    {
        last.addr = (void *) find_sandbox_start("[heap]");;
    }

  if (pm == NULL || last.addr == NULL) {    
    return SANDBOX_ERR_INVALID;
  }
  
  /* next mmap should be on a page boundary at least one page
     higher than the end of the previous map */

  next.addr =
    (void *) ((uint64_t) ((last.addr + last.size) + 0x1000) & PAGE_MASK);

  /* used for limit checking */
  next.size = (pm->size + 0x1000) & PAGE_MASK;
  DMSG ("next addr determined to be %p; size to be %lx\n",
	next.addr, next.size);

  if (((uint64_t) next.addr) + next.size >= ultimate_limit)
    {
      /* do not update last.*, preserve the previous 
       * value so we can use it again */
      pm->size = 0L;
      pm->addr = MAP_FAILED;
      DMSG ("mmap would exceed 32-bit near jump limit %lx\n", ultimate_limit);
      return SANDBOX_ERR_INVALID;
    }

  pm->addr = mmap (next.addr, next.size,
		   PROT_READ | PROT_WRITE | PROT_EXEC,
		   MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED, 0, 0);


  if (pm->addr == MAP_FAILED)
    {
      DMSG ("mmap failed addr %p, size %lx\n", next.addr, next.size);
      return SANDBOX_ERR_NOMEM;
    }

  last.addr = pm->addr;
  last.size = pm->size;
  DMSG ("mmap suceeded, addr %p, size %lx\n", last.addr, last.size);

  return SANDBOX_OK;
}

int
unmap_patch_map (struct patch_map *pm)
{
  int ccode = SANDBOX_OK;
  if (pm->addr != NULL)
    ccode = munmap (pm->addr, pm->size);
  else
    pm->addr = NULL;
  pm->size = 0;
  return ccode;
}


int
init_sandbox ()
{
  LIST_INIT (&lp_patch_head);

  return SANDBOX_OK;
}

FILE *log_fd = NULL;
int log_level = 1;		/* mirror log to stdout */
int DEBUG = 1;

int
set_loglevel (int l)
{
  int old = log_level;
  log_level = l;
  return old;
}


int
set_debug (int db)
{
  int old = DEBUG;
  DEBUG = db;
  printf ("debug messages are %s\n", db > 0 ? "on" : "off");
  return old;
}



FILE *
open_log (void)
{
  char lpath[0x32];
  snprintf (lpath, 0x32, "sand_log_%d", getpid ());
  log_fd = fopen (lpath, "a");
  return log_fd;
}


void
DMSG (char *fmt, ...)
{
  if (DEBUG)
    {
      va_list va;
      va_start (va, fmt);
      vfprintf (stderr, fmt, va);
      va_end (va);

    }
}

extern void va_copy (va_list dest, va_list src);
void
LMSG (char *fmt, ...)
{
  va_list va;

  if (log_fd == NULL)
    {
      DMSG ("opening log file\n");
      log_fd = open_log ();
      if (log_fd == NULL)
	{
	  DMSG ("could not open log file\n");
	  perror (NULL);
	  return;
	}
    }
  if (log_level > 0)
    {
      va_list vb;
      va_start (vb, fmt);
      vfprintf (stdout, fmt, vb);
      va_end (vb);
    }

  va_start (va, fmt);
  vfprintf (log_fd, fmt, va);
  va_end (va);

}


void
bin2hex (unsigned char *bin, size_t binlen, char *buf, size_t buflen)
{
  static const char hexchars[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < binlen; i++, bin++)
    {
      /* Ensure we can fit two characters and the terminating nul */
      if (buflen >= 3)
	{
	  *buf++ = hexchars[(*bin >> 4) & 0x0f];
	  *buf++ = hexchars[*bin & 0x0f];

	  buflen -= 2;
	}
    }

  if (buflen)
    *buf = 0;
}


void
hex2bin (char *buf, size_t buflen, unsigned char *bin, size_t binlen)
{

  int count = 0, sha_count = 0;
  char *p = buf;

  while (count <= buflen && sha_count <= binlen)
    {
      bin[sha_count] = htoi (*(p + count));
      count += 4;
      sha_count++;
    }
}

void
make_text_writeable (struct xenlp_patch_write *writes, uint32_t numwrites)
{
  int i;
  for (i = 0; i < numwrites; i++)
    {
      struct xenlp_patch_write *pwrite = &writes[i];
      uintptr_t write_ptr = (uintptr_t) pwrite->hvabs;
      write_ptr &= PLATFORM_PAGE_MASK;
      if (mprotect ((void *) write_ptr, PLATFORM_PAGE_SIZE,
		    PROT_READ | PROT_EXEC | PROT_WRITE))
	{
	  perror ("err: ");
	}
    }
}

void
swap_trampolines (struct xenlp_patch_write *writes, uint32_t numwrites)
{
  int i;
  for (i = 0; i < numwrites; i++)
    {
      struct xenlp_patch_write *pw = &writes[i];

      uint64_t old_data;
      __atomic_exchange ((uint64_t *) pw->hvabs, (uint64_t *) pw->data,
			 &old_data, __ATOMIC_RELAXED);
      memcpy (pw->data, &old_data, sizeof (pw->data));
    }
}


void
dump_sandbox (const void *data, size_t size)
{
  char ascii[17];
  size_t i, j;
  if (DEBUG < 1)
    return;

  ascii[16] = '\0';
  printf ("\n");
  printf ("%08lx\t", (unsigned long) (unsigned char *) data);
  for (i = 0; i < size; ++i)
    {
      printf ("%02X ", ((unsigned char *) data)[i]);
      if (((unsigned char *) data)[i] >= ' '
	  && ((unsigned char *) data)[i] <= '~')
	{
	  ascii[i % 16] = ((unsigned char *) data)[i];
	}
      else
	{
	  ascii[i % 16] = '.';
	}
      if ((i + 1) % 8 == 0 || i + 1 == size)
	{
	  printf (" ");
	  if ((i + 1) % 16 == 0 && i + 1 < size)
	    {
	      printf ("|  %s \n%08lx\t", ascii,
		      (unsigned long) (((unsigned char *) data) + i));
	    }
	  else if (i + 1 == size)
	    {
	      ascii[(i + 1) % 16] = '\0';
	      if ((i + 1) % 16 <= 8)
		{
		  printf (" ");
		}
	      for (j = (i + 1) % 16; j < 16; ++j)
		{
		  printf ("   ");
		}
	      printf ("\n");

	    }

	}
    }
}



/* Note: this is ported from xen-livepatch. */

int
read_patch_data (XEN_GUEST_HANDLE (void) * arg,
		 struct xenlp_apply4 *apply, struct patch_map *pm,
		 struct xenlp_patch_write **writes_p)
{
  size_t i;
  int32_t relocrel = 0;
  int ccode = SANDBOX_OK;
  uintptr_t runtime_constant = 0;

  /* Blobs are optional */
  if (apply->bloblen)
    {
      pm->size = apply->bloblen;
      ccode = map_patch_map (pm);

      if (ccode != SANDBOX_OK)
	{
	  DMSG ("error allocating %d bytes memory in read_patch_data\n",
		apply->bloblen);
	  return ccode;
	}

      /* Copy blob to .txt using the map */
      memcpy (pm->addr, arg, pm->size);
      /* Skip over blob */
      arg = (unsigned char *) arg + apply->bloblen;
      runtime_constant = (uintptr_t) & _start - (uintptr_t) apply->refabs;
      apply->refabs += runtime_constant;
      /* Calculate offset of relocations */
      relocrel = (uintptr_t) (pm->addr) - apply->refabs;

    }

  /* Read relocs */
  if (apply->numrelocs)
    {
      uint32_t *relocs = calloc (apply->numrelocs, sizeof (*relocs));
      if (!relocs)
	{
	  DMSG ("error allocating %d bytes in read_patch_data\n",
		apply->numrelocs * sizeof (uint32_t));
	  ccode = SANDBOX_ERR_NOMEM;
	  goto errout;
	}

      memcpy (relocs, arg, apply->numrelocs * sizeof (relocs[0]));


      arg = (unsigned char *) arg + (apply->numrelocs * sizeof (relocs[0]));

      for (i = 0; i < apply->numrelocs; i++)
	{
	  uint32_t off = relocs[i];
	  if (off > apply->bloblen - sizeof (int32_t))
	    {
	      DMSG ("invalid off value %d\n", off);
	      ccode = SANDBOX_ERR_INVALID;
	      goto errout;
	    }

	  /* blob -> HV .text */
	  *((int32_t *) (pm->addr + off)) -= relocrel;
	}

      free (relocs);
    }

  /* Read writes */

  /* Read writes */
  ccode = posix_memalign ((void **) writes_p,
			  __alignof__ (struct xenlp_patch_write),
			  sizeof (struct xenlp_patch_write) *
			  apply->numwrites);

  if (ccode != 0)
    {
      DMSG ("error allocating %d bytes in read_patch_data\n",
	    apply->numwrites * sizeof (struct xenlp_patch_write));
      ccode = SANDBOX_ERR_NOMEM;
      goto errout;
    }
  memcpy (*writes_p, arg,
	  apply->numwrites * sizeof (struct xenlp_patch_write));

  /* Move over all of the writes */
  arg = (unsigned char *) arg + (apply->numwrites * sizeof ((*writes_p)[0]));

  /* Verify writes and apply any relocations in writes */
  for (i = 0; i < apply->numwrites; i++)
    {
      struct xenlp_patch_write *pw = &((*writes_p)[i]);
      char off = pw->dataoff;

      pw->hvabs += runtime_constant;
      if (pw->hvabs < (uintptr_t) & _start || pw->hvabs >= (uintptr_t) & _end)
	{
	  DMSG ("invalid hvabs value %lx\n", pw->hvabs);
	  ccode = SANDBOX_ERR_INVALID;
	  goto errout;
	}
      if (off < 0)
	continue;

      /* HV .text -> blob */
      switch (pw->reloctype)
	{
	case XENLP_RELOC_UINT64:
	  if (off > sizeof (pw->data) - sizeof (uint64_t))
	    {
	      DMSG ("invalid dataoff value %d\n", off);
	      ccode = SANDBOX_ERR_INVALID;
	      goto errout;
	    }
	  *((uint64_t *) (pw->data + off)) += relocrel;
	  break;
	case XENLP_RELOC_INT32:
	  if (off > sizeof (pw->data) - sizeof (int32_t))
	    {
	      DMSG ("invalid dataoff value %d\n", off);
	      ccode = SANDBOX_ERR_INVALID;
	      goto errout;
	    }
	  *((int32_t *) (pw->data + off)) += relocrel;
	  break;
	default:
	  printk ("unknown reloctype value %u\n", pw->reloctype);
	  ccode = SANDBOX_ERR_INVALID;
	  goto errout;
	}
    }
  return ccode;
errout:
  unmap_patch_map (pm);
  free (*writes_p);
  *writes_p = NULL;
  return ccode;
}



int
xenlp_apply4 (void *arg)
{
  struct xenlp_apply4 apply;
  struct xenlp_patch_write *writes = NULL;
  struct applied_patch *patch = NULL;
  char sha1[SHA_DIGEST_LENGTH * 2 + 1];
  int ccode = SANDBOX_OK;
  struct patch_map pm = { NULL, 0 };

  memcpy (&apply, arg, sizeof (struct xenlp_apply4));

  if (apply.bloblen > MAX_PATCH_SIZE)
    {
      DMSG ("live patch size %u is too large\n", apply.bloblen);
      return SANDBOX_ERR_INVALID;
    }
  /* Skip over struct xenlp_apply4 */
  arg = (unsigned char *) arg + sizeof (struct xenlp_apply4);
  /* Do some initial sanity checking */
  if (apply.numwrites == 0)
    {
      DMSG ("need at least one patch\n");
      return SANDBOX_ERR_INVALID;
    }
  /* we don't expect any exception tables for user space. 
   * need to have an exception table size of zero, and skip
   */
  if (apply.numexctblents != 0 || apply.numpreexctblents != 0)
    {
      return SANDBOX_ERR_INVALID;
    }


  patch = calloc (1, sizeof (struct applied_patch));
  if (!patch)
    {
      DMSG ("unable to allocate %d bytes in xenlp_apply4\n",
	    sizeof (struct applied_patch));
      return SANDBOX_ERR_NOMEM;
    }

  ccode = read_patch_data (arg, &apply, &pm, &writes);

  if (ccode != SANDBOX_OK)
    {
      DMSG ("fault %d reading patch data\n", ccode);
      goto errout;
    }

  /* Read dependencies */
  patch->numdeps = apply.numdeps;
  DMSG ("numdeps: %d\n", apply.numdeps);
  if (apply.numdeps > 0)
    {
      int ccode = posix_memalign ((void **) &(patch->deps),
				  __alignof__ (*(patch->deps)),
				  sizeof (*(patch->deps)) * apply.numdeps);

      DMSG ("posix_memalign returned %d\n", ccode);

      if (ccode != SANDBOX_OK || !patch->deps)
	{
	  DMSG ("error allocating memory for patch dependencies\n");
	  ccode = SANDBOX_ERR_NOMEM;
	  if (ccode)		/* this read is just to satisfy scan-build */
	    goto errout;
	}

      if (memcpy
	  (patch->deps, arg, apply.numdeps * sizeof (struct xenlp_hash)))
	{
	  DMSG ("fault copying memory in xenlp_apply3\n");
	  ccode = SANDBOX_ERR_INVALID;
	  if (ccode)		/* this read is just to satisfy scan-build */
	    goto errout;
	}
      arg =
	(unsigned char *) arg + (apply.numdeps * sizeof (struct xenlp_hash));
    }

  /* Read tags */
  patch->tags[0] = 0;
  DMSG ("taglen: %d\n", apply.taglen);
  if (apply.taglen > 0 && apply.taglen <= MAX_TAGS_LEN)
    {
      memcpy (patch->tags, arg, apply.taglen);
      patch->tags[apply.taglen] = '\0';
      DMSG ("tags: %s\n", patch->tags);
    }

  make_text_writeable (writes, apply.numwrites);
  /* Nothing should be possible to fail now, so do all of the writes */

/* note - no exception table entries to write */
  swap_trampolines (writes, apply.numwrites);

  /* copy the patch map */
  patch->map = pm;
  memcpy (patch->sha1, apply.sha1, sizeof (patch->sha1));
  patch->numwrites = apply.numwrites;
  patch->writes = writes;

  LIST_INSERT_HEAD (&lp_patch_head, patch, l);
  bin2hex (apply.sha1, sizeof (apply.sha1), sha1, sizeof (sha1));
  printk ("successfully applied patch %s\n", sha1);

  return ccode;
errout:
  unmap_patch_map (&pm);
  if (patch != NULL)
    {
      free (patch->writes);
      free (patch->deps);
      free (patch);
    }
  return ccode;
}

int
has_dependent_patches (struct applied_patch *patch)
{
  /* Starting from current patch, looking down the linked list
   * Find if any later patches depend on this one */
  struct applied_patch *ap = LIST_NEXT (patch, l);

  while (ap && ap != LIST_FIRST (&lp_patch_head))
    {
      size_t i;
      for (i = 0; i < ap->numdeps; i++)
	{
	  struct xenlp_hash *dep = &ap->deps[i];
	  if (memcmp (dep->sha1, patch->sha1, sizeof (patch->sha1)) == 0)
	    return 1;
	}
      ap = LIST_NEXT (ap, l);
    }
  return 0;
}


int
xenlp_undo4 (XEN_GUEST_HANDLE (void *)arg)
{
  struct xenlp_hash hash;
  struct applied_patch *ap;

  memcpy (&hash, arg, sizeof (struct xenlp_hash));

  LIST_FOREACH (ap, &lp_patch_head, l)
  {
    if (memcmp (ap->sha1, hash.sha1, sizeof (hash.sha1)) == 0)
      {
	if (has_dependent_patches (ap) || ap->numwrites == 0)
	  return -ENXIO;
	swap_trampolines (ap->writes, ap->numwrites);
	LIST_REMOVE (ap, l);
	free (ap->writes);
	free (ap->deps);
	unmap_patch_map (&ap->map);
	free (ap);
	return 0;
      }
  }
  return -ENOENT;
}
