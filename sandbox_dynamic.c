#include <stdio.h>
#include <sys/mman.h>
#include "sandbox.h"

/* every patch is located in a memory-mapped (anonymous) file 
 * every map has an address and a size
 * to find a corresponding applied patch, search for applied_patch3 ==
 * patch_map.addr
 */

struct patch_map 
{
  void * addr;
  uint64_t size;
  struct list_head l;
};

/* keep each map on  linked list */
LIST_HEAD (maps);


/* list_add (&patch->l, &lp_patch_head3);
 * && ap != list_first_entry (&lp_patch_head3,
 * list_for_each_entry (ap, &lp_patch_head3, l)
 */
struct patch_map *
allocate_patch_map(unsigned int size)
{
  struct patch_map *pm = malloc(sizeof(struct patch_map));
  if (pm == NULL) 
    {
      return pm;
    }
  pm->size = size;
  pm->addr = mmap (NULL, size,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  
  if (pm->adr == MAP_FAILED)
    goto err_out;
  list_add (&pm->l, &maps);
  return pm->addr;
  
 err_out:
  free(pm);
  return MAP_FAILED;
}

int
free_patch_map(void *address)
{
  struct patch_map *pmap;
  int ccode = SANDBOX_OK;
  
  list_for_each_entry (pmap, &maps, l) 
    {
      if (pmap-addr == address)
        {
          list_del(&pmap->l);
          ccode = munmap(pmap->addr, pmap->size);
          free(pmap);d
          return ccode;
        }
    }
  return ccode;
}

struct applied_patch3 *
get_patch_from_map(void *blob)
{
  struct applied_patch3 * ap = NULL;
  list_for_each_entry(ap, &lp_patch_head3, l)
    {
      if (ap->blob == blob) 
        {
          return ap;
        }
    }
  return ap;
}

struct applied_patch3 *
get_patch_from_map(void *addr)
{
  struct applied_patch3 * ap = NULL;
  list_for_each_entry(ap, &lp_patch_head3, l)
    {
      if (ap->blob == blob) 
        {
          return ap;
        }
    }
  return ap;
}


struct patch_map *
get_map_from_patch(void *blob)
{
  struct patch_map * pm = NULL;
  list_for_each_entry(pm, &maps, l)
    {
      if (pm->addr == blob) 
        {
          return pm;
        }
    }
  return pm;
}



typedef unsigned (*asmFunc) (void);

int
main (int argc, char *argv[])
{
  // probably needs to be page aligned...

  unsigned int codeBytes = 4096;
  void *virtualCodeAddress = 0;

  virtualCodeAddress = mmap (NULL,
                             codeBytes,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

  printf ("virtualCodeAddress = %p\n", virtualCodeAddress);

  // write some code in
  unsigned char *tempCode = (unsigned char *) (virtualCodeAddress);
  tempCode[0] = 0xb8;
  tempCode[1] = 0x00;
  tempCode[2] = 0x11;
  tempCode[3] = 0xdd;
  tempCode[4] = 0xee;
  // ret code! Very important!
  tempCode[5] = 0xc3;

  asmFunc myFunc = (asmFunc) (virtualCodeAddress);

  unsigned out = myFunc ();

  printf ("out is %x\n", out);

  return 0;
}
