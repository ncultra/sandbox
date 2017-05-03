#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <signal.h>
#include <sched.h>
#include <memory.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <ctype.h>

/* every patch is located in a memory-mapped (anonymous) file 
 * every map has an address and a size
 * to find a corresponding applied patch, search for applied_patch3 ==
 * patch_map.addr
 */

struct patch_map
{
  void *addr;
  uint64_t size;
    LIST_ENTRY (patch_map) l;
};

struct applied_patch3
{
  void *blob;
  unsigned char sha1[20];	/* binary encoded */
  uint32_t numwrites;
  struct xenlp_patch_write *writes;
  uint32_t numdeps;
  struct xenlp_hash *deps;
  char tags[100];
    LIST_ENTRY (applied_patch3) l;
};

struct applied_patch3 *
allocate_applied_patch (void *blob)
{
  struct applied_patch3 *ap;
  ap = calloc (1, sizeof (struct applied_patch3));
  if (ap == NULL)
    goto out;
  ap->blob = blob;
out:
  return ap;
}

int
free_applied_patch (struct applied_patch3 *ap)
{
  /* blob is a patch map, don't free here */
  free (ap);
  return 0;
}

struct patch_map *
allocate_patch_map (unsigned int size)
{
  struct patch_map *pm = malloc (sizeof (struct patch_map));
  if (pm == NULL)
    {
      return NULL;
    }
  pm->size = size;
  pm->addr = mmap (NULL, size,
		   PROT_READ | PROT_WRITE | PROT_EXEC,
		   MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

  if (pm->addr == MAP_FAILED)
    goto err_out;
  return pm;

err_out:
  free (pm);
  return MAP_FAILED;
}

int free_patch_map (struct patch_map *pm) __attribute__ ((used));

int
free_patch_map (struct patch_map *pm)
{
  int ccode = munmap (pm->addr, pm->size);
  free (pm);
  return ccode;
}

/* keep each map on  linked list */
struct maps_h
{
  struct patch_map *lh_first;
};


struct lp_patch_head3_h
{
  struct applied_patch3 *lh_first;
};


typedef unsigned (*asmFunc) (void);

int
main (int argc, char *argv[])
{
  int i;
  unsigned int codeBytes = 0x1000;
  struct patch_map *pm;
  struct applied_patch3 *ap3;

  struct maps_h maps;
  struct lp_patch_head3_h lp_patch_head3;

  LIST_INIT (&maps);
  LIST_INIT (&lp_patch_head3);


  for (i = 0; i < 10; i++)
    {

      pm = allocate_patch_map (codeBytes);
      if (pm == NULL)
	return 0;

      LIST_INSERT_HEAD (&maps, pm, l);

      ap3 = allocate_applied_patch (pm->addr);
      if (ap3 == NULL)
	{
	  LIST_REMOVE (pm, l);
	  free_patch_map (pm);
	  return 0;
	}
      LIST_INSERT_HEAD (&lp_patch_head3, ap3, l);


      printf ("patch %p; blob = %p\n", ap3, ap3->blob);

      // write some code in
      unsigned char *tempCode = (unsigned char *) (ap3->blob);
      tempCode[0] = 0xb8;
      tempCode[1] = 0x00;
      tempCode[2] = 0x11;
      tempCode[3] = 0xdd;
      tempCode[4] = 0xee;
      // ret code! Very important!
      tempCode[5] = 0xc3;

      asmFunc myFunc = (asmFunc) (ap3->blob);
      unsigned out = myFunc ();
      printf ("out is %x\n", out);
    }

  LIST_FOREACH (pm, &maps, l)
  {
    printf ("map %p\n", pm);
  }

  LIST_FOREACH (ap3, &lp_patch_head3, l)
  {
    printf ("patch %p; blob %p\n", ap3, ap3->blob);
  }

  while (!LIST_EMPTY (&lp_patch_head3))
    {
      ap3 = LIST_FIRST (&lp_patch_head3);
      printf ("removing applied patch %p\n", ap3);
      LIST_REMOVE (ap3, l);
      free_applied_patch (ap3);
    }

  while (!LIST_EMPTY (&maps))
    {
      pm = LIST_FIRST (&maps);
      printf ("removing patch map %p\n", pm);
      LIST_REMOVE (pm, l);
      free_patch_map (pm);
    }


  return 0;
}
