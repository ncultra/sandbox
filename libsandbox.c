#include <sys/mman.h>
#include "atomic.h"
#include "sandbox.h"

/* #define str1(s) #s
#define str(s) str1(s)
*/
extern uintptr_t _start, _end;

/* head of list of applied patches */
struct lph lp_patch_head3;

uintptr_t
ALIGN_POINTER (uintptr_t p, uintptr_t offset)
{
  if (!p % offset)
    return p;
  p += (offset - 1);
  p &= ~(offset - 1);
  return p;
}




int
map_patch_map (struct patch_map *pm)
{
  if (pm == NULL)
    return SANDBOX_ERR_INVALID;

  pm->addr = mmap (NULL, pm->size,
		   PROT_READ | PROT_WRITE | PROT_EXEC,
		   MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  if (pm->addr == MAP_FAILED)
    return SANDBOX_ERR_NOMEM;

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
  LIST_INIT (&lp_patch_head3);

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
		  struct xenlp_apply3 *apply, struct patch_map *pm,
		  struct xenlp_patch_write **writes_p)
{
  size_t i;
  uintptr_t relocrel = 0;
  uintptr_t runtime_constant = 0;
  int ccode;

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
       blob (new) - _start (relocated) =	 (1) in the scratch pad

       relocrel is also necessary to normalize distances in the
       new code.

       runtime_constant: the difference in refabs before and after relocation.
       used as a sanity check, may be removed at a later time.

       relocrel  blob_p - refabs: distance from _start (refabs) to the new code
       (landing in the sandbox) at runtime (abs).

  ***/
  /* Blobs are optional */
  if (apply->bloblen)
    {
      if (!pm || !writes_p || !apply || !arg)
	{
	  DMSG ("error invalid parameters in read_patch_data\n");
	  return SANDBOX_ERR_INVALID;
	}

      pm->size = apply->bloblen;
      ccode = map_patch_map (pm);

      if (ccode != SANDBOX_OK)
	{
	  DMSG ("error allocating %d bytes memory in read_patch_data\n",
		apply->bloblen);
	  return ccode;
	}

      DMSG ("read_patch_data2: blob: %p arg: %p len: %d\n",
	    pm->addr, arg, pm->size);


      /* Copy blob to .txt using the map */
      memcpy (pm->addr, arg, pm->size);

      /* Skip over blob */
      arg = (unsigned char *) arg + pm->size;


      DMSG ("adjusting refabs, before: %lx\n", apply->refabs);
      runtime_constant = (uintptr_t) & _start - (uintptr_t) apply->refabs;
      apply->refabs += runtime_constant;
      DMSG ("refabs adjusted: %lx\n", apply->refabs);
    }

  relocrel = (uintptr_t) (pm->addr - apply->refabs);
  DMSG ("relocrel: %lx (%ld)\n", relocrel, relocrel);

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
      uintptr_t off = 0;
      for (i = 0; i < apply->numrelocs; i++)
	{
	  off = relocs[i];
	  if (off > pm->size - sizeof (int32_t))
	    {
	      printk ("invalid off value %d\n", off);
	      free (relocs);
	      ccode = -EINVAL;
	      goto errout;
	    }

	  uint32_t *blob_value = (pm->addr + off);

	  /* blob -> HV .text  - adjust absolute offsets to this process mem */
	  DMSG
	    ("Normalizing 32-bit offset from blob to _start to the blob\n");
	  DMSG ("value before write: %lx\n", *blob_value);
	  *blob_value -= (uint32_t) relocrel;
	  DMSG ("value after write: %lx\n", *blob_value);
	}

      free (relocs);
    }

  /* Read writes */
  posix_memalign ((void **) &(*writes_p),
		  __alignof__ (struct xenlp_patch_write),
		  sizeof (struct xenlp_patch_write) * apply->numwrites);

  if (!(*writes_p))
    {
      DMSG ("error allocating %d bytes in read_patch_data\n",
	    apply->numwrites * sizeof (struct xenlp_patch_write));
      ccode = SANDBOX_ERR_NOMEM;
      goto errout;
    }
  memcpy (*writes_p, arg,
	  apply->numwrites * sizeof (struct xenlp_patch_write));

  /* Move over all of the writes */
  /* Verify writes and apply any relocations in writes

     pw->hvabs = resting address of function to be patched, (jmp location)
     pw->data contains the jmp instruction to apply
     pw->dataoff needs the offset within pw->data where to place the jmp distance

     relocrel at this point is the distance of the mapped memory  to the
     reference (_start)
   */
  for (i = 0; i < apply->numwrites; i++)
    {
      struct xenlp_patch_write *pw = &((*writes_p)[i]);
      int8_t off = pw->dataoff;
      /* adjust the hvabs to the runtime (after 1st relocation) */
      pw->hvabs += runtime_constant;

      if (pw->hvabs < (uintptr_t) & _start || pw->hvabs >= (uintptr_t) & _end)
	{
	  DMSG ("invalid hvabs value %lx\n", pw->hvabs);
	  ccode = SANDBOX_ERR_INVALID;
	  goto errout;
	}

      if (off < 0)
	continue;


      /* HV .text -> map */
      switch (pw->reloctype)
	{
	case XENLP_RELOC_UINT64:

	  if (off > sizeof (pw->data) - sizeof (uint64_t))
	    {
	      DMSG ("invalid dataoff value %d\n", off);
	      ccode = SANDBOX_ERR_INVALID;
	      goto errout;

	    }
	  /* update the jmp distance within the patch write */
	  /* relocrel should be the distance between pw->hvabs and blob */

	  DMSG ("jmp distance within 64-bit patch buf before write: %lx\n",
		*((uint64_t *) (pw->data + off)));

	  *((uint64_t *) (pw->data + off)) += (uintptr_t) relocrel;

	  DMSG ("jmp distance within 64-bit patch buf AFTER write: %lx \n",
		*((uint64_t *) (pw->data + off)));

	  break;
	case XENLP_RELOC_INT32:
	  if (off > sizeof (pw->data) - sizeof (int32_t))
	    {
	      DMSG ("invalid dataoff value %d\n", off);
	      ccode = SANDBOX_ERR_INVALID;
	      goto errout;
	    }
	  DMSG ("jmp distance within 32-bit patch buf before write: %lx\n",
		*((int32_t *) (pw->data + off)));

	  *((int32_t *) (pw->data + off)) += relocrel;

	  DMSG ("jmp distance within 32-bit patch buf AFTER write: %lx\n",
		*((int32_t *) (pw->data + off)));
	  break;
	default:

	  DMSG ("unknown reloctype value %u\n", pw->reloctype);
	  ccode = SANDBOX_ERR_INVALID;
	  goto errout;
	}
    }

  return SANDBOX_OK;
errout:
  unmap_patch_map (pm);
  free (*writes_p);
  *writes_p = NULL;
  return ccode;
}

int
xenlp_apply3 (void *arg)
{
  struct xenlp_apply3 apply;
  struct xenlp_patch_write *writes = NULL;
  struct applied_patch3 *patch = NULL;
  char sha1[SHA_DIGEST_LENGTH * 2 + 1];
  int ccode = SANDBOX_ERR;
  struct patch_map pm = { NULL, 0 };

  memcpy (&apply, arg, sizeof (struct xenlp_apply3));

  /* Skip over struct xenlp_apply3 */
  arg = (unsigned char *) arg + sizeof (struct xenlp_apply3);
  /* Do some initial sanity checking */
  if (apply.numwrites == 0)
    {
      DMSG ("need at least one patch\n");
      ccode = SANDBOX_ERR_INVALID;
      goto errout;
    }

  patch = calloc (1, sizeof (struct applied_patch3));
  if (!patch)
    {
      DMSG ("unable to allocate %d bytes in xenlp_apply3\n",
	    sizeof (struct xenlp_apply3));
      ccode = SANDBOX_ERR_NOMEM;
      goto errout;
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
      posix_memalign ((void **) &(patch->deps),
		      __alignof__ (*(patch->deps)),
		      sizeof (*(patch->deps)) * apply.numdeps);

      if (!patch->deps)
	{
	  DMSG ("error allocating memory for patch dependencies\n");
	  ccode = SANDBOX_ERR_NOMEM;
	  goto errout;
	}

      if (memcpy
	  (patch->deps, arg, apply.numdeps * sizeof (struct xenlp_hash)))
	{
	  DMSG ("fault copying memory in xenlp_apply3\n");
	  ccode = SANDBOX_ERR_INVALID;
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
  swap_trampolines (writes, apply.numwrites);

  /* copy the patch map */
  patch->map = pm;
  memcpy (patch->sha1, apply.sha1, sizeof (patch->sha1));
  patch->numwrites = apply.numwrites;
  patch->writes = writes;

  LIST_INSERT_HEAD (&lp_patch_head3, patch, l);
  bin2hex (apply.sha1, sizeof (apply.sha1), sha1, sizeof (sha1));
  printk ("successfully applied patch %s\n", sha1);

  return SANDBOX_OK;
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
has_dependent_patches (struct applied_patch3 *patch)
{
  /* Starting from current patch, looking down the linked list
   * Find if any later patches depend on this one */
  struct applied_patch3 *ap = LIST_NEXT (patch, l);

  while (ap && ap != LIST_FIRST (&lp_patch_head3))
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
xenlp_undo3 (XEN_GUEST_HANDLE (void *)arg)
{
  struct xenlp_hash hash;
  struct applied_patch3 *ap;

  memcpy (&hash, arg, sizeof (struct xenlp_hash));

  LIST_FOREACH (ap, &lp_patch_head3, l)
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
