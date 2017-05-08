#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h>
#include <limits.h>
#include <sys/fcntl.h>

#include <zlib.h>

#include <libelf.h>

#include <openssl/sha.h>

#include "util.h"
#include "patch_file.h"
#include "../sandbox.h"
#include "portability.h"

typedef int xc_interface_t;
static int json = 0;

int
do_lp_list3 (xc_interface_t xch, struct xenlp_list3 *list)
{
  return __do_lp_list3 (xch, list);
}


int
do_lp_caps (xc_interface_t xch, struct xenlp_caps *caps)
{
  return __do_lp_caps (xch, caps);
}


int
do_lp_apply3 (xc_interface_t xch, void *buf, size_t buflen)
{
  return __do_lp_apply3 (xch, buf, buflen);
}

int
do_lp_apply4 (xc_interface_t xch, void *buf, size_t buflen)
{
  return __do_lp_apply4 (xch, buf, buflen);
}

int
do_lp_undo3 (xc_interface_t xch, void *buf, size_t buflen)
{
  return __do_lp_undo3 (xch, buf, buflen);
}

void
usage (void)
{
  printf ("\nraxlpxs --info --list --apply <patch> \
--remove <patch> --socket <sockname>  --debug --help\n");
  exit (0);
}


int
find_patch3 (xc_interface_t xch, unsigned char *sha1, size_t sha1_size,
	     struct xenlp_patch_info3 **patch)
{
  /* Do a list first and make sure patch isn't already applied yet */
  struct xenlp_list3 list = {.skippatches = 0 };

  int ret = do_lp_list3 (xch, &list);
  if (ret < 0)
    {
      fprintf (stderr, "failed to get list: %m\n");
      return -1;
    }

  int totalpatches = 0;
  while (1)
    {
      int i;
      for (i = 0; i < list.numpatches; i++)
	{
	  struct xenlp_patch_info3 *pi = &list.patches[i];
	  /* int j; this is from the original file, appears to be extraneous */

	  if (memcmp (pi->sha1, sha1, sha1_size) == 0)
	    {
	      *patch = pi;
	      return 0;
	    }

	  totalpatches++;
	}

      if (list.numpatches < MAX_LIST_PATCHES)
	break;

      list.skippatches = totalpatches;

      ret = do_lp_list3 (xch, &list);
      if (ret < 0)
	{
	  fprintf (stderr, "failed to get list: %m\n");
	  return -1;
	}
    }
  return 0;
}


#define ADR(d, s)	do { memcpy(ptr, d, s); ptr += s; } while (0)
#define AD(d)		ADR(&d, sizeof(d))
#define ADA(d, n)	ADR(d, sizeof(d[0]) * n)
#if 0
size_t
fill_patch_buf3 (unsigned char *buf, struct patch3 * patch,
		 uint32_t numwrites, struct xenlp_patch_write * writes)
{
  size_t i;
  unsigned char *ptr = buf;
  struct xenlp_apply3 apply = {
  bloblen:patch->bloblen,

  numrelocs:patch->numrelocs,
  numwrites:numwrites,

  refabs:patch->refabs,
  numdeps:patch->numdeps,
  taglen:strnlen (patch->tags,
	     MAX_TAGS_LEN - 1)
  };

  size_t buflen = sizeof (apply) + patch->bloblen +
    (patch->numrelocs * sizeof (patch->relocs[0])) +
    (numwrites * sizeof (writes[0])) +
    (patch->numdeps * sizeof (patch->deps[0])) + apply.taglen;

  if (buf == NULL)
    return buflen;

  memcpy (apply.sha1, patch->sha1, sizeof (apply.sha1));

  AD (apply);			/* struct xenlp_apply */
  if (patch->bloblen > 0)
    ADR (patch->blob, patch->bloblen);	/* blob */
  if (patch->numrelocs > 0)
    ADA (patch->relocs, patch->numrelocs);	/* relocs */
  if (numwrites > 0)
    ADA (writes, numwrites);	/* writes */
  if (apply.numdeps > 0)
    {
      struct xenlp_hash *deps =
	_zalloc (sizeof (struct xenlp_hash) * apply.numdeps);
      for (i = 0; i < apply.numdeps; i++)
	memcpy (deps[i].sha1, patch->deps[i].sha1,
		sizeof (patch->deps[i].sha1));
      ADA (deps, apply.numdeps);	/* deps */
      free (deps);
    }
  if (apply.taglen > 0)
    ADR (patch->tags, apply.taglen);
  return (ptr - buf);
}
#endif

size_t
fill_patch_buf3 (unsigned char *buf, struct patch * patch,
		 uint32_t numwrites, struct xenlp_patch_write * writes)
{
  size_t i;
  unsigned char *ptr = buf;
  struct xenlp_apply3 apply = {
  bloblen:patch->bloblen,

  numrelocs:patch->numrelocs,
  numwrites:numwrites,

  refabs:patch->refabs,
  numdeps:patch->numdeps,
  taglen:strnlen (patch->tags, MAX_TAGS_LEN - 1)
  };

  size_t buflen = sizeof (apply) + patch->bloblen +
    (patch->numrelocs * sizeof (patch->relocs[0])) +
    (numwrites * sizeof (writes[0])) +
    (patch->numdeps * sizeof (patch->deps[0])) + apply.taglen;

  if (buf == NULL)
    return buflen;

  memcpy (apply.sha1, patch->sha1, sizeof (apply.sha1));

  AD (apply);			/* struct xenlp_apply3 */
  if (patch->bloblen > 0)
    ADR (patch->blob, patch->bloblen);	/* blob */
  if (patch->numrelocs > 0)
    ADA (patch->relocs, patch->numrelocs);	/* relocs */
  if (numwrites > 0)
    ADA (writes, numwrites);	/* writes */
  if (apply.numdeps > 0)
    {
      struct xenlp_hash *deps = _zalloc (sizeof (struct xenlp_hash) *
					 apply.numdeps);
      for (i = 0; i < apply.numdeps; i++)
	memcpy (deps[i].sha1, patch->deps[i].sha1,
		sizeof (patch->deps[i].sha1));
      ADA (deps, apply.numdeps);	/* deps */
      free (deps);
    }
  if (apply.taglen > 0)
    ADR (patch->tags, apply.taglen);
  return (ptr - buf);
}

size_t
fill_patch_buf4 (unsigned char *buf, struct patch * patch,
		 uint32_t numwrites, struct xenlp_patch_write * writes)
{
  size_t i;
  unsigned char *ptr = buf;
  struct xenlp_apply4 apply = {
  bloblen:patch->bloblen,

  numrelocs:patch->numrelocs,
  numwrites:numwrites,

  numexctblents:patch->numexctblents,
  numpreexctblents:patch->numpreexctblents,

  refabs:patch->refabs,
  numdeps:patch->numdeps,
  taglen:strnlen (patch->tags, MAX_TAGS_LEN - 1),
  };

  size_t buflen = sizeof (apply) + patch->bloblen +
    (patch->numrelocs * sizeof (patch->relocs[0])) +
    (numwrites * sizeof (writes[0])) +
    (patch->numexctblents * sizeof (struct xenlp_exctbl_entry)) +
    (patch->numpreexctblents * sizeof (struct xenlp_exctbl_entry)) +
    (patch->numdeps * sizeof (patch->deps[0])) + apply.taglen;

  if (buf == NULL)
    return buflen;

  memcpy (apply.sha1, patch->sha1, sizeof (apply.sha1));

  AD (apply);			/* struct xenlp_apply4 */
  if (patch->bloblen > 0)
    ADR (patch->blob, patch->bloblen);	/* blob */
  if (patch->numrelocs > 0)
    ADA (patch->relocs, patch->numrelocs);	/* relocs */
  if (numwrites > 0)
    ADA (writes, numwrites);	/* writes */
  if (apply.numexctblents > 0)
    {
      struct xenlp_exctbl_entry *exctblents;
      exctblents = _zalloc (sizeof (struct xenlp_exctbl_entry) *
			    apply.numexctblents);
      for (i = 0; i < apply.numexctblents; i++)
	{
	  exctblents[i].addrrel = patch->exctblents[i].addrrel;
	  exctblents[i].contrel = patch->exctblents[i].contrel;
	}
      ADA (exctblents, apply.numexctblents);
      free (exctblents);
    }
  if (apply.numpreexctblents > 0)
    {
      struct xenlp_exctbl_entry *exctblents;
      exctblents = _zalloc (sizeof (struct xenlp_exctbl_entry) *
			    apply.numpreexctblents);
      for (i = 0; i < apply.numpreexctblents; i++)
	{
	  exctblents[i].addrrel = patch->preexctblents[i].addrrel;
	  exctblents[i].contrel = patch->preexctblents[i].contrel;
	}
      ADA (exctblents, apply.numpreexctblents);
      free (exctblents);
    }
  if (apply.numdeps > 0)
    {
      struct xenlp_hash *deps = _zalloc (sizeof (struct xenlp_hash) *
					 apply.numdeps);
      for (i = 0; i < apply.numdeps; i++)
	memcpy (deps[i].sha1, patch->deps[i].sha1,
		sizeof (patch->deps[i].sha1));
      ADA (deps, apply.numdeps);	/* deps */
      free (deps);
    }
  if (apply.taglen > 0)
    ADR (patch->tags, apply.taglen);
  return (ptr - buf);
}

void
patch_writes (struct patch *patch, struct xenlp_patch_write *writes)
{
  size_t i;
  for (i = 0; i < patch->numfuncs; i++)
    {
      struct function_patch *func = &patch->funcs[i];
      struct xenlp_patch_write *pw = &writes[i];

      pw->hvabs = func->oldabs;

      /* Create jmp trampoline */
      /* jmps are relative to next instruction, so subtract out 5 bytes
       * for the jmp instruction itself */
      int32_t jmpoffset = (patch->refabs + func->newrel) - func->oldabs - 5;

      pw->data[0] = 0xe9;	/* jmp instruction */
      memcpy (&pw->data[1], &jmpoffset, sizeof (jmpoffset));

      pw->reloctype = XENLP_RELOC_INT32;
      pw->dataoff = 1;

      printf ("Patching function %s @ %llx\n", func->funcname,
	      (long long unsigned int) func->oldabs);
    }
}


#if 0
int
_cmd_apply3 (xc_interface_t xch, struct patch3 *patch)
{
  size_t i;
  struct xenlp_patch_info3 *info = NULL;
  /* Do a list first and make sure patch isn't already applied yet */
  if (find_patch3 (xch, patch->sha1, sizeof (patch->sha1), &info) < 0)
    {
      fprintf (stderr, "error: could not search for patches\n");
      return -1;
    }
  if (info)
    {
      printf ("Patch already applied, skipping\n");
      return 0;
    }
  /* Search for dependent patches, calculate relative address for each */
  for (i = 0; i < patch->numdeps; i++)
    {
      struct xenlp_patch_info3 *dep_patch = NULL;
      if (find_patch3
	  (xch, patch->deps[i].sha1,
	   sizeof (patch->deps[i].sha1), &dep_patch) < 0)
	{
	  fprintf (stderr, "error: could not search for patches\n");
	  return -1;
	}
      if (dep_patch == NULL)
	{
	  char sha1str[SHA_DIGEST_LENGTH * 2 + 1];
	  bin2hex (patch->deps[i].sha1,
		   sizeof (patch->deps[i].sha1), sha1str, sizeof (sha1str));
	  fprintf (stderr,
		   "error: dependency was not found in memory: "
		   "patch %s\n", sha1str);
	  return -1;
	}
      /* Update the relative address */
      patch->deps[i].reladdr =
	(uint32_t) (dep_patch->hvaddr - patch->deps[i].refabs);
    }

  for (i = 0; i < patch->numrelocs3; i++)
    {
      struct reloc3 *rel3 = &patch->relocs3[i];
      if (rel3->index >= patch->numdeps)
	{
	  fprintf (stderr,
		   "error: invalid second level relocation "
		   "at %d: %d\n", rel3->index, rel3->offset);
	  return -1;
	}
      /* Patch blob-related relocation here, we already know the
       * relative address */
      *((int32_t *) (patch->blob + rel3->offset)) +=
	patch->deps[rel3->index].reladdr;
      printf ("Patching dependent relocation to +%x @ %x\n",
	      patch->deps[rel3->index].reladdr, rel3->offset);
      patch->relocs[patch->numrelocs + i] = rel3->offset;
    }
  patch->numrelocs += patch->numrelocs3;

  /* Convert into a series of writes for the live patch functionality */
  uint32_t numwrites = patch->numfuncs;
  struct xenlp_patch_write writes[numwrites];
  memset (writes, 0, sizeof (writes));
  patch_writes (&patch->v2, writes);

  size_t buflen = fill_patch_buf3 (NULL, patch, numwrites, writes);
  unsigned char *buf = _zalloc (buflen);
  buflen = fill_patch_buf3 (buf, patch, numwrites, writes);

  int ret = do_lp_apply3 (xch, buf, buflen);
  if (ret < 0)
    {
      fprintf (stderr, "failed to patch hypervisor: %m\n");
      return -1;
    }
  return 0;
}

#endif


int
_cmd_apply3 (xc_interface_t xch, struct patch *patch)
{
  size_t i;
  struct xenlp_patch_info3 *info = NULL;

  if (patch->numexctblents || patch->numpreexctblents)
    {
      fprintf (stderr, "error: patch uses exception tables, but apply3 "
	       "does not support\n");
      return -1;
    }

  /* Do a list first and make sure patch isn't already applied yet */
  if (find_patch3 (xch, patch->sha1, sizeof (patch->sha1), &info) < 0)
    {
      fprintf (stderr, "error: could not search for patches\n");
      return -1;
    }
  if (info)
    {
      printf ("Patch already applied, skipping\n");
      return 0;
    }
  /* Search for dependent patches, calculate relative address for each */
  for (i = 0; i < patch->numdeps; i++)
    {
      struct xenlp_patch_info3 *dep_patch = NULL;
      if (find_patch3 (xch, patch->deps[i].sha1, sizeof (patch->deps[i].sha1),
		       &dep_patch) < 0)
	{
	  fprintf (stderr, "error: could not search for patches\n");
	  return -1;
	}
      if (dep_patch == NULL)
	{
	  char sha1str[SHA_DIGEST_LENGTH * 2 + 1];
	  bin2hex (patch->deps[i].sha1, sizeof (patch->deps[i].sha1),
		   sha1str, sizeof (sha1str));
	  fprintf (stderr, "error: dependency was not found in memory: "
		   "patch %s\n", sha1str);
	  return -1;
	}
      /* Update the relative address */
      patch->deps[i].reladdr =
	(uint32_t) (dep_patch->hvaddr - patch->deps[i].refabs);
    }

  for (i = 0; i < patch->numrelocs3; i++)
    {
      struct reloc3 *rel3 = &patch->relocs3[i];
      if (rel3->index >= patch->numdeps)
	{
	  fprintf (stderr, "error: invalid second level relocation "
		   "at %d: %d\n", rel3->index, rel3->offset);
	  return -1;
	}
      /* Patch blob-related relocation here, we already know the
       * relative address */
      *((int32_t *) (patch->blob + rel3->offset)) +=
	patch->deps[rel3->index].reladdr;
      printf ("Patching dependent relocation to +%x @ %x\n",
	      patch->deps[rel3->index].reladdr, rel3->offset);
      patch->relocs[patch->numrelocs + i] = rel3->offset;
    }
  patch->numrelocs += patch->numrelocs3;

  /* Convert into a series of writes for the live patch functionality */
  uint32_t numwrites = patch->numfuncs;
  struct xenlp_patch_write writes[numwrites];
  memset (writes, 0, sizeof (writes));
  patch_writes (patch, writes);

  size_t buflen = fill_patch_buf3 (NULL, patch, numwrites, writes);
  unsigned char *buf = _zalloc (buflen);
  buflen = fill_patch_buf3 (buf, patch, numwrites, writes);

  int ret = do_lp_apply3 (xch, buf, buflen);
  if (ret < 0)
    {
      fprintf (stderr, "failed to patch hypervisor: %m\n");
      return -1;
    }
  return 0;
}


int
_cmd_apply4 (xc_interface_t xch, struct patch *patch)
{
  size_t i;
  struct xenlp_patch_info3 *info = NULL;

  /* Do a list first and make sure patch isn't already applied yet */
  if (find_patch3 (xch, patch->sha1, sizeof (patch->sha1), &info) < 0)
    {
      fprintf (stderr, "error: could not search for patches\n");
      return -1;
    }
  if (info)
    {
      printf ("Patch already applied, skipping\n");
      return 0;
    }
  /* Search for dependent patches, calculate relative address for each */
  for (i = 0; i < patch->numdeps; i++)
    {
      struct xenlp_patch_info3 *dep_patch = NULL;
      if (find_patch3 (xch, patch->deps[i].sha1, sizeof (patch->deps[i].sha1),
		       &dep_patch) < 0)
	{
	  fprintf (stderr, "error: could not search for patches\n");
	  return -1;
	}
      if (dep_patch == NULL)
	{
	  char sha1str[SHA_DIGEST_LENGTH * 2 + 1];
	  bin2hex (patch->deps[i].sha1, sizeof (patch->deps[i].sha1),
		   sha1str, sizeof (sha1str));
	  fprintf (stderr, "error: dependency was not found in memory: "
		   "patch %s\n", sha1str);
	  return -1;
	}
      /* Update the relative address */
      patch->deps[i].reladdr =
	(uint32_t) (dep_patch->hvaddr - patch->deps[i].refabs);
    }

  for (i = 0; i < patch->numrelocs3; i++)
    {
      struct reloc3 *rel3 = &patch->relocs3[i];
      if (rel3->index >= patch->numdeps)
	{
	  fprintf (stderr, "error: invalid second level relocation "
		   "at %d: %d\n", rel3->index, rel3->offset);
	  return -1;
	}
      /* Patch blob-related relocation here, we already know the
       * relative address */
      *((int32_t *) (patch->blob + rel3->offset)) +=
	patch->deps[rel3->index].reladdr;
      printf ("Patching dependent relocation to +%x @ %x\n",
	      patch->deps[rel3->index].reladdr, rel3->offset);
      patch->relocs[patch->numrelocs + i] = rel3->offset;
    }
  patch->numrelocs += patch->numrelocs3;

  /* Convert into a series of writes for the live patch functionality */
  uint32_t numwrites = patch->numfuncs;
  struct xenlp_patch_write writes[numwrites];
  memset (writes, 0, sizeof (writes));
  patch_writes (patch, writes);

  size_t buflen = fill_patch_buf4 (NULL, patch, numwrites, writes);
  unsigned char *buf = _zalloc (buflen);
  buflen = fill_patch_buf4 (buf, patch, numwrites, writes);

  int ret = do_lp_apply4 (xch, buf, buflen);
  if (ret < 0)
    {
      fprintf (stderr, "failed to patch hypervisor: %m\n");
      return -1;
    }
  return 0;
}





int
cmd_apply (int sockfd, char *path)
{

  char filepath[PATH_MAX];
  int xch = sockfd;

  /* basename() can modify its argument, so make a copy */
  strncpy (filepath, path, sizeof (filepath) - 1);
  filepath[sizeof (filepath) - 1] = 0;
  const char *filename = basename (filepath);

  int fd = open (filepath, O_RDONLY);
  if (fd < 0)
    {
      fprintf (stderr, "error: open(%s): %m\n", filepath);
      return -1;
    }

  struct patch patch;
/* TODO: should be able to load the patch using a full path,
 * not just the basename
 */
  if (load_patch_file (fd, filename, &patch) < 0)
    return -1;
  close (fd);


/* check for QEMU version and sandbox build info */
  LMSG ("Getting QEMU/sandbox info\n");

  char *qemu_version = get_qemu_version (xch);
  char *qemu_compile_date = get_qemu_date (xch);

  if (!strlen (qemu_version) || !strlen (qemu_compile_date))
    {
      LMSG ("error getting version and complilation data\n");
      return SANDBOX_ERR_RW;
    }


  LMSG ("  QEMU Version: %s\n", qemu_version);
  LMSG ("  QEMU Compile Date: %s\n", qemu_compile_date);

  LMSG ("\n");
  LMSG ("Patch Applies To:\n");
  LMSG ("  QEMU Version: %s\n", patch.xenversion);
  LMSG ("  QEMU  Compile Date: %s\n", patch.xencompiledate);
  LMSG ("\n");

/* extract_patch limits the info strings to 32 bytes each */
  if (strncmp (qemu_version, patch.xenversion, INFO_EXTRACT_LEN) != 0
      || strncmp (qemu_compile_date, patch.xencompiledate,
		  INFO_EXTRACT_LEN) != 0)
    {
      LMSG ("error: patch does not match QEMU build\n");
      return SANDBOX_ERR_BAD_VER;
    }

  /* Perform some sanity checks */
  if (patch.crowbarabs != 0)
    {
      fprintf (stderr, "error: cannot handle crowbar style patches\n");
      return -1;
    }

  if (patch.numchecks > 0)
    {
      fprintf (stderr, "error: cannot handle prechecks\n");
      return -1;
    }

  /* FIXME: Handle hypercall table writes too */
  if (patch.numtables > 0)
    {
      fprintf (stderr, "error: cannot handle table writes, yet\n");
      return -1;
    }

  struct xenlp_caps caps = {.flags = 0 };
  do_lp_caps (xch, &caps);
  if (caps.flags & XENLP_CAPS_V3)
    {
      if (_cmd_apply3 (xch, &patch) < 0)
	return -1;
    }
  else
    {
      DMSG ("error: using v2 livepatch ABI\n");
      return -1;
    }

  char sha1str[SHA_DIGEST_LENGTH * 2 + 1];
  bin2hex (patch.sha1, sizeof (patch.sha1), sha1str, sizeof (sha1str));
  printf ("\nSuccessfully applied patch %s\n", sha1str);
  return 0;
}


static void
print_list_header ()
{
  if (json)
    printf ("[");
  else
    {
      printf ("Applied patches\n");
      printf ("===============\n");
    }
}


static void
print_list_footer ()
{
  if (json)
    printf ("]\n");
}



void
print_patch_info3 (struct xenlp_patch_info3 *pi, int last)
{
  unsigned char sha1zero[SHA_DIGEST_LENGTH] = { 0 };
  int j;

  if (json)
    printf ("\n  {\"sha1\": \"");

  for (j = 0; j < sizeof (pi->sha1); j++)
    printf ("%02x", pi->sha1[j]);

  if (json)
    {
      printf ("\",");
      printf (" \"tags\": \"%s\",", pi->tags);
    }
  else
    printf (" [%s]", pi->tags);

  for (j = 0; j < MAX_LIST_DEPS; j++)
    {
      if (memcmp (pi->deps[j].sha1, sha1zero, SHA_DIGEST_LENGTH) == 0)
	break;
      char hex[SHA_DIGEST_LENGTH * 2 + 1];
      bin2hex (pi->deps[j].sha1, SHA_DIGEST_LENGTH, hex, sizeof (hex));
      if (json)
	{
	  printf (" \"dep\": \"%s\",", hex);
	}
      else
	printf (" dep: %s", hex);
    }
  if (json)
    printf (" \"hvaddr\": \"0x%llx\"}%s",
	    (long long unsigned) pi->hvaddr, ((last) ? "\n" : ","));
  else
    printf (" @ %llx\n", (long long unsigned) pi->hvaddr);
}


int
_cmd_list3 (xc_interface_t xch)
{
  struct xenlp_list3 list = {.skippatches = 0 };

  int ret = do_lp_list3 (xch, &list);
  if (ret < 0)
    {
      fprintf (stderr, "failed to get list: %m\n");
      return -1;
    }

  print_list_header ();
  int totalpatches = 0;
  int last = 0;
  while (1)
    {
      int i;
      for (i = 0; i < list.numpatches; i++)
	{
	  struct xenlp_patch_info3 *pi = &list.patches[i];
	  if (list.numpatches < MAX_LIST_PATCHES && i == list.numpatches - 1)
	    last = 1;
	  print_patch_info3 (pi, last);
	  totalpatches++;
	}

      if (list.numpatches < MAX_LIST_PATCHES3)
	break;

      list.skippatches = totalpatches;

      ret = do_lp_list3 (xch, &list);
      if (ret < 0)
	{
	  fprintf (stderr, "failed to get list: %m\n");
	  return -1;
	}
    }
  print_list_footer ();
  return 0;
}

int
cmd_list (int argc, char *argv[])
{
  xc_interface_t xch;
  if (open_xc (&xch) < 0)
    return -1;
  struct xenlp_caps caps = {.flags = 0 };
  do_lp_caps (xch, &caps);
  if (caps.flags & XENLP_CAPS_V3)
    return _cmd_list3 (xch);

  fprintf (stderr, "warn:  v2 livepatch ABI is obsolete\n");
  return -1;

}


int
info_patch_file (int fd, const char *filename)
{
  struct patch patch;
  /* size_t i; is apparently unused in the upstream file */
  if (load_patch_file (fd, filename, &patch) < 0)
    return -1;
  close (fd);

  if (json)
    print_json_patch_info (&patch);
  else
    print_patch_file_info (&patch);
  return 0;
}

int
_cmd_undo3 (xc_interface_t xch, struct xenlp_hash *hash,
	    const unsigned char *patch_hash)
{
  struct xenlp_patch_info3 *info = NULL;
  if (find_patch3 (xch, hash->sha1, SHA_DIGEST_LENGTH, &info) < 0)
    {
      fprintf (stderr, "error: could not search for patches\n");
      return -1;
    }
  if (!info)
    {
      fprintf (stderr, "%s: patch not found in memory\n", patch_hash);
      return -1;
    }
  printf ("Un-applying patch:\n  ");
  print_patch_info3 (info, 1);

  size_t buflen = sizeof (struct xenlp_hash);
  unsigned char *buf = _zalloc (buflen);
  memcpy (buf, hash, buflen);

  int ret = do_lp_undo3 (xch, buf, buflen);
  if (ret < 0)
    {
      if (errno == ENOENT)
	{
	  fprintf (stderr,
		   "failed to undo a hypervisor patch: " "patch not found\n");
	  return -1;
	}
      else if (errno == ENXIO)
	{
	  fprintf (stderr,
		   "failed to undo a hypervisor patch: "
		   "undo dependent patches first\n");
	  return -1;
	}
      else
	{
	  fprintf (stderr, "failed to undo a hypervisor patch: %m\n");
	  return -1;
	}
    }
  return 0;
}


/* sha1 will be a string in the sandbox case */
int
cmd_undo (int sockfd, unsigned char *sha1)
{

  int ccode = 0;
  unsigned char *sha1hex = NULL;

  /* this needs to be a copy */
  sha1hex = (unsigned char *) strdup ((char *) sha1);
  if (string2sha1 ((char *) sha1hex, sha1) < 0)
    {
      ccode = -1;
      goto out;
    }

  /* sockfd will already be open if we get here */

  xc_interface_t xch = sockfd;

  struct xenlp_hash hash = { {0} };
  memcpy (hash.sha1, sha1, SHA_DIGEST_LENGTH);

  struct xenlp_caps caps = {.flags = 0 };
  do_lp_caps (xch, &caps);
  if (caps.flags & XENLP_CAPS_V3)
    {
      if (_cmd_undo3 (xch, &hash, sha1hex) < 0)
	{
	  ccode = -1;
	  goto out;
	}
    }
  else
    {
      fprintf (stderr, "error: no v3 ABI detected, undo disabled\n");
      ccode = -1;
      goto out;
    }
  LMSG ("\n successfully un-applied patch %s\n", sha1hex);

out:
  if (sha1hex != NULL)
    free (sha1hex);
  return ccode;
}


/***********************************************
 * with QEMU we need a more flexible way to pass args,
 * we have at least a socket as an additional arg.
 * So, just use the cmdline from raxlpqemu
 *********************************************/
static int info_flag, list_flag, find_flag, apply_flag, remove_flag,
  sock_flag;
static char filepath[PATH_MAX];
static char patch_basename[PATH_MAX];
static unsigned char patch_hash[SHA_DIGEST_LENGTH * 2 + 1];
char sockname[PATH_MAX];
extern int sockfd;

/* There is no defined order for options on the command line
 * so, we need to process all the options (except --help) before
 * running any of the commands. iow, don't run commands in the options
 * switch, run them after done processing options.
 *
 * Options can be short or long, for example --socket and -s are the same.
 * Options that require a parameter, for example socket name, must see
 * the parameter before the next option appears on the command line.
 * e.g., --socket <sockname> or --apply <patchfile>
 */

static inline void
get_options (int argc, char **argv)
{
  while (1)
    {
      if (argc < 2)
	usage ();

      int c;
      static struct option long_options[] = {
	{"dummy-for-short-option", no_argument, NULL, 0},
	{"info", no_argument, &info_flag, 1},
	{"list", no_argument, &list_flag, 1},
	{"find", required_argument, &find_flag, 1},
	{"apply", required_argument, &apply_flag, 1},
	{"remove", required_argument, &remove_flag, 1},
	{"socket", required_argument, &sock_flag, 1},
	{"debug", no_argument, NULL, 0},
	{"help", no_argument, NULL, 0},
	{0, 0, 0, 0}
      };
      int option_index = 0;
      c = getopt_long_only (argc, argv, "ila:f:u:s:dh",
			    long_options, &option_index);
      if (c == -1)
	{
	  break;
	}

    restart_long:
      switch (option_index)
	{
	case 0:
	  switch (c)
	    {
	    case 'i':
	      option_index = 1;
	      info_flag = 1;
	      goto restart_long;
	    case 'l':
	      option_index = 2;
	      list_flag = 1;
	      goto restart_long;
	    case 'f':
	      option_index = 3;
	      find_flag = 1;
	      goto restart_long;
	    case 'a':
	      option_index = 4;
	      apply_flag = 1;
	      goto restart_long;
	    case 'r':
	      option_index = 5;
	      remove_flag = 1;
	      goto restart_long;
	    case 's':
	      option_index = 6;
	      goto restart_long;
	    case 'd':
	      option_index = 7;
	      goto restart_long;
	    case 'h':
	      option_index = 8;
	      goto restart_long;
	    default:
	      break;
	      usage ();
	    }
	  DMSG ("selected option %s\n", long_options[option_index].name);
	case 1:		/* info */
	  {
	    info_flag = 1;
	    DMSG ("selected option %s\n", long_options[option_index].name);
	  }
	  break;

	case 2:		/* list */
	  list_flag = 1;
	  DMSG ("selected option %s\n", long_options[option_index].name);
	  break;
	case 3:		/* find */
	  {
	    find_flag = 1;
	    DMSG ("selected option %s\n", long_options[option_index].name);
	    strncpy ((char *) patch_hash, optarg, SHA_DIGEST_LENGTH * 2 + 1);
	    DMSG ("find patch %s\n", patch_hash);
	    break;
	  }
	case 4:		/* apply */
	  {
	    strncpy (filepath, optarg, sizeof (filepath) - 1);
	    /* TODO: clean up basename handling - detect errors */
	    char *basep = basename (filepath);
	    if (basep != NULL)
	      {
		strncpy (patch_basename, basep, PATH_MAX);
	      }
	    DMSG ("patch file: %s\n", patch_basename);
	    break;
	  }
	case 5:		/* remove */
	  {
	    strncpy ((char *) patch_hash, optarg, SHA_DIGEST_LENGTH * 2 + 1);
	    DMSG ("remove  patch: %s \n", patch_hash);
	    break;
	  }
	case 6:		/* set socket */
	  {
	    strncpy (sockname, optarg, PATH_MAX);
	    DMSG ("socket: %s\n", sockname);
	    break;
	  }
	case 7:
	  {
	    set_debug (1);
	    break;

	  }
	case 8:
	  {
	    usage ();		/* usage exits */
	    break;
	  }
	default:
	  break;
	}
    }
}

int
main (int argc, char **argv)
{

  int ccode;
  get_options (argc, argv);

  if (sock_flag == 0 || (sockfd = connect_to_sandbox (sockname)) < 0)
    {
      DMSG
	("error connecting to sandbox server, did you specify the socket? \n");
      return SANDBOX_ERR_RW;
    }

  /* we don't run these functions within the option switch because */
  /* we rely on having the sockname set, which can happen after other options */
  if (info_flag > 0)
    {
      /* info for xenlp inspects the patch file */
      /* this is a little different, it returns the QEMU build info strings */

      DMSG ("calling get_info_strings with handle: %d\n", sockfd);

      int info = get_info_strings (sockfd, 1);
      if (info != SANDBOX_OK)
	{
	  LMSG ("error getting build info\n");
	}
    }

  if (list_flag > 0)
    {

      if ((ccode = _cmd_list3 (sockfd)) < 0)
	{
	  LMSG ("error listing applied patches\n");
	}
    }


  if (find_flag > 0)
    {
      struct xenlp_patch_info3 *patch_buf = NULL;
      unsigned char sha1[SHA_DIGEST_LENGTH + 2] = { 0 };
      DMSG ("WHAT THE BUTT\n");

      string2sha1 ((char *) patch_hash, sha1);

      ccode = find_patch (sockfd, sha1, SHA_DIGEST_LENGTH, &patch_buf);
      if (ccode == 1)
	{
	  DMSG ("found patch: %s\n", patch_hash);
	  /* TODO: print all patch info int txt, json */
	}
      else if (ccode == 0)
	{
	  DMSG ("Not found: %s\n", patch_hash);
	}
      else if (patch_buf < 0)
	{
	  DMSG ("error in find_patch: %d\n", ccode);
	}
      if (patch_buf != NULL)
	{
	  free (patch_buf);
	}
    }
  if (apply_flag > 0)
    {
      if ((ccode = cmd_apply (sockfd, filepath)) < 0)
	{
	  DMSG ("error applying patch %d\n", ccode);
	}
      else
	{
	  LMSG ("Patch %s successfully applied\n", filepath);
	}
    }
  if (remove_flag > 0)
    {
      /* getopt should have copied the sha1 hex string to patch_hash */
      /* cmd_undo */
      if ((ccode = cmd_undo (sockfd, patch_hash)) < 0)
	{
	  LMSG ("Error reversing patch %s\n", patch_hash);
	}

    }
  if (sockfd > 0)
    {
      close (sockfd);
      sockfd = 0;
    }

  LMSG ("bye\n");
  return SANDBOX_OK;

}
