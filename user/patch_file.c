#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "patch_file.h"
#include "util.h"


int
_read (int fd, const char *filename, void *buf, size_t buflen)
{
  ssize_t ret = read (fd, buf, buflen);
  if (ret < 0)
    {
      fprintf (stderr, "%s: %m\n", filename);
      return -1;
    }
  if (ret < buflen)
    {
      fprintf (stderr, "%s: expected %d bytes, read %d\n",
	       filename, (int) buflen, (int) ret);
      return -1;
    }

  return 0;
}


int
_readu64 (int fd, const char *filename, uint64_t * value)
{
  unsigned char buf[sizeof (uint64_t)];

  if (_read (fd, filename, buf, sizeof (buf)) < 0)
    return -1;

  *value = ((uint64_t) buf[0]) << 56 | ((uint64_t) buf[1]) << 48 |
    ((uint64_t) buf[2]) << 40 | ((uint64_t) buf[3]) << 32 |
    ((uint64_t) buf[4]) << 24 | ((uint64_t) buf[5]) << 16 |
    ((uint64_t) buf[6]) << 8 | ((uint64_t) buf[7]);
  return 0;
}


int
_readu32 (int fd, const char *filename, uint32_t * value)
{
  unsigned char buf[sizeof (uint32_t)];

  if (_read (fd, filename, buf, sizeof (buf)) < 0)
    return -1;

  *value = ((uint32_t) buf[0]) << 24 | ((uint32_t) buf[1]) << 16 |
    ((uint32_t) buf[2]) << 8 | ((uint32_t) buf[3]);
  return 0;
}


int
_readu16 (int fd, const char *filename, uint16_t * value)
{
  unsigned char buf[sizeof (uint16_t)];

  if (_read (fd, filename, buf, sizeof (buf)) < 0)
    return -1;

  *value = ((uint16_t) buf[0]) << 8 | ((uint16_t) buf[1]);
  return 0;
}


static int
extract_sha1_from_filename (unsigned char *sha1, size_t sha1len,
			    const char *filename)
{

  /* Make sure suffix is .raxlpxs */
  if (strstr (filename, ".raxlpxs") == NULL)
    {
      fprintf (stderr, "error: missing .raxlpxs extension: "
	       "filename must be of form <sha1>.raxlpxs\n");
      return -1;
    }

  /* Make sure filename length is 48: 40 (<sha1>) + 8 ('.raxlpxs') */
  if (strlen (filename) != 48)
    {
      fprintf (stderr, "error: filename must be of form <sha1>.raxlpxs\n");
      return -1;
    }

  return string2sha1 (filename, sha1);
}


static int
get_patch_version (int fd, const char *filename)
{
  char signature[XSPATCH_COOKIE_LEN];
  off_t cur = lseek (fd, 0, SEEK_CUR);
  lseek (fd, 0, SEEK_SET);

  if (_read (fd, filename, signature, sizeof (signature)) < 0)
    return -1;

  lseek (fd, cur, SEEK_SET);

  if (memcmp (signature, XSPATCH_COOKIE3, sizeof (signature)) == 0)
    return 3;
  else if (memcmp (signature, XSPATCH_COOKIE4, sizeof (signature)) == 0)
    return 4;

  return -1;
}


static off_t
calc_file_size (int fd, const char *filename)
{
  struct stat st;

  if (fstat (fd, &st) < 0)
    {
      fprintf (stderr, "%s: stat(): %m\n", filename);
      return -1;
    }

  return st.st_size;
}


static int
calc_block_sha1 (int fd, const char *filename, off_t start,
		 off_t end, unsigned char *hash)
{
  off_t file_size = calc_file_size (fd, filename);

  if (start < 0 || end < 0 || end < start || end > file_size)
    {
      fprintf (stderr, "%s: invalid start/end for sha1 calculation\n",
	       filename);
      return -1;
    }

  off_t cur = lseek (fd, 0, SEEK_CUR);
  lseek (fd, start, SEEK_SET);

  SHA_CTX sha1;
  SHA1_Init (&sha1);

  size_t bytesread = 0;
  off_t size = end - start;

  while (bytesread < size)
    {
      unsigned char buf[4096];
      size_t readsize = sizeof (buf);
      if (size - bytesread < readsize)
	readsize = size - bytesread;

      if (_read (fd, filename, buf, readsize) < 0)
	return -1;

      SHA1_Update (&sha1, buf, readsize);
      bytesread += readsize;
    }

  SHA1_Final (hash, &sha1);
  lseek (fd, cur, SEEK_SET);
  return 0;
}


static int
calculate_file_sha1 (int fd, const char *filename, unsigned char *hash)
{
  off_t file_size = calc_file_size (fd, filename);
  return calc_block_sha1 (fd, filename, 0, file_size, hash);
}


static int
read_refxen_data (int fd, const char *filename, struct patch *patch)
{
  /* Read Xen version and compile date */
  if (_read (fd, filename, patch->xenversion, sizeof (patch->xenversion)) < 0)
    return -1;

  if (_read (fd, filename, patch->xencompiledate,
	     sizeof (patch->xencompiledate)) < 0)
    return -1;
  return 0;
}


static int
read_blob_data (int fd, const char *filename, struct patch *patch)
{
  /* Pull the blob out */
  if (_readu32 (fd, filename, &patch->bloblen) < 0)
    return -1;

  patch->blob = _zalloc (patch->bloblen);
  if (_read (fd, filename, patch->blob, patch->bloblen) < 0)
    return -1;
  return 0;
}


static int
read_reloc_data (int fd, const char *filename, struct patch *patch)
{
  /* Pull out second-stage relocations */
  if (_readu16 (fd, filename, &patch->numrelocs) < 0)
    return -1;

  patch->relocs = _zalloc (patch->numrelocs * sizeof (uint32_t));
  size_t i;
  for (i = 0; i < patch->numrelocs; i++)
    {
      if (_readu32 (fd, filename, &patch->relocs[i]) < 0)
	return -1;
    }
  return 0;
}


static int
read_check_data (int fd, const char *filename, struct patch *patch)
{
  size_t i;
  /* Pull out check data. Only used for crowbar */
  if (_readu16 (fd, filename, &patch->numchecks) < 0)
    return -1;

  patch->checks = _zalloc (sizeof (struct check) * patch->numchecks);
  for (i = 0; i < patch->numchecks; i++)
    {
      struct check *check = &patch->checks[i];

      if (_readu64 (fd, filename, &check->hvabs) < 0)
	return -1;
      if (_readu16 (fd, filename, &check->datalen) < 0)
	return -1;

      check->data = _zalloc (check->datalen);
      if (_read (fd, filename, check->data, check->datalen) < 0)
	return -1;
    }
  return 0;
}


static int
read_func_data (int fd, const char *filename, struct patch *patch)
{
  size_t i;
  /* Pull out function to patch */
  if (_readu16 (fd, filename, &patch->numfuncs) < 0)
    return -1;

  patch->funcs = _zalloc (patch->numfuncs * sizeof (patch->funcs[0]));
  for (i = 0; i < patch->numfuncs; i++)
    {
      struct function_patch *func = &patch->funcs[i];

      uint16_t size;
      if (_readu16 (fd, filename, &size) < 0)
	return -1;
      func->funcname = _zalloc (size + 1);
      if (_read (fd, filename, func->funcname, size) < 0)
	return -1;

      if (_readu64 (fd, filename, &func->oldabs) < 0)
	return -1;
      if (_readu32 (fd, filename, &func->newrel) < 0)
	return -1;
    }
  return 0;
}


static int
read_table_data (int fd, const char *filename, struct patch *patch)
{
  size_t i;
  /* Pull out table patches. Only used for crowbar currently */
  if (_readu16 (fd, filename, &patch->numtables) < 0)
    return -1;

  patch->tables = _zalloc (sizeof (struct table_patch) * patch->numtables);
  for (i = 0; i < patch->numtables; i++)
    {
      struct table_patch *table = &patch->tables[i];

      uint16_t tablenamelen;
      if (_readu16 (fd, filename, &tablenamelen) < 0)
	return -1;

      table->tablename = _zalloc (tablenamelen + 1);
      if (_read (fd, filename, table->tablename, tablenamelen) < 0)
	return -1;

      if (_readu64 (fd, filename, &table->hvabs) < 0)
	return -1;
      if (_readu16 (fd, filename, &table->datalen) < 0)
	return -1;

      table->data = _zalloc (table->datalen);
      if (_read (fd, filename, table->data, table->datalen) < 0)
	return -1;
    }
  return 0;
}


static int
_load_patch_file2 (int fd, const char *filename, struct patch *patch)
{
  int version = get_patch_version (fd, filename);
  if (version != XSPATCH_VER2)
    {
      fprintf (stderr, "%s: invalid signature\n", filename);
      return -1;
    }

  if (extract_sha1_from_filename (patch->sha1, sizeof (patch->sha1),
				  filename) < 0)
    return -1;

  /* Calculate SHA1 hash and verify it matches filename */
  unsigned char hash[SHA_DIGEST_LENGTH];
  if (calculate_file_sha1 (fd, filename, hash) < 0)
    return -1;

  if (memcmp (patch->sha1, hash, sizeof (patch->sha1)) != 0)
    {
      char hex[SHA_DIGEST_LENGTH * 2 + 1];
      fprintf (stderr, "%s: hash mismatch\n", filename);
      bin2hex (hash, sizeof (hash), hex, sizeof (hex));
      fprintf (stderr, "  calculated %s\n", hex);
      return -1;
    }

  lseek (fd, XSPATCH_COOKIE_LEN, SEEK_SET);

  if (read_refxen_data (fd, filename, patch) < 0)
    return -1;

  /* Only used for crowbar, ignored in this utility */
  if (_readu64 (fd, filename, &patch->crowbarabs) < 0)
    return -1;

  /* Virtual address used for first-stage relocation */
  if (_readu64 (fd, filename, &patch->refabs) < 0)
    return -1;

  if (read_blob_data (fd, filename, patch) < 0)
    return -1;

  if (read_reloc_data (fd, filename, patch) < 0)
    return -1;

  if (read_check_data (fd, filename, patch) < 0)
    return -1;

  if (read_func_data (fd, filename, patch) < 0)
    return -1;

  if (read_table_data (fd, filename, patch) < 0)
    return -1;

  return 0;
}


static int
extract_sha1_from_patch (unsigned char *sha1, size_t sha1len,
			 int fd, const char *filename)
{
  off_t cur = lseek (fd, 0, SEEK_CUR);
  off_t end = lseek (fd, 0, SEEK_END);
  if (end < sha1len)
    {
      fprintf (stderr, "error: patch file %s is too short\n", filename);
      return -1;
    }

  lseek (fd, -(SHA_DIGEST_LENGTH), SEEK_END);

  if (_read (fd, filename, sha1, sha1len) < 0)
    return -1;

  lseek (fd, cur, SEEK_SET);
  return 0;
}


static int
read_tag_data (int fd, const char *filename, struct patch *patch)
{
  uint16_t size;
  if (_readu16 (fd, filename, &size) < 0)
    return -1;

  patch->tags = _zalloc (size + 1);
  if (_read (fd, filename, patch->tags, size) < 0)
    return -1;
  return 0;
}


static int
read_deps_data (int fd, const char *filename, struct patch *patch)
{
  size_t i;
  if (_readu16 (fd, filename, &patch->numdeps) < 0)
    return -1;

  patch->deps = _zalloc (sizeof (struct dependency) * patch->numdeps);
  for (i = 0; i < patch->numdeps; i++)
    {
      struct dependency *dep = &patch->deps[i];
      if (_read (fd, filename, &dep->sha1, sizeof (dep->sha1)) < 0)
	return -1;
      if (_readu64 (fd, filename, &dep->refabs) < 0)
	return -1;
      dep->reladdr = 0;
    }
  return 0;
}


static int
read_reloc_data3 (int fd, const char *filename, struct patch *patch)
{
  size_t i;
  if (_readu16 (fd, filename, &patch->numrelocs3) < 0)
    return -1;

  patch->relocs3 = _zalloc (sizeof (struct reloc3) * patch->numrelocs3);
  for (i = 0; i < patch->numrelocs3; i++)
    {
      struct reloc3 *reloc = &patch->relocs3[i];
      if (_readu16 (fd, filename, &reloc->index) < 0)
	return -1;
      if (_readu32 (fd, filename, &reloc->offset) < 0)
	return -1;
    }

  if (_readu16 (fd, filename, &patch->numrelocs) < 0)
    return -1;

  uint16_t rel_count = patch->numrelocs + patch->numrelocs3;
  patch->relocs = _zalloc (rel_count * sizeof (uint32_t));
  for (i = 0; i < patch->numrelocs; i++)
    {
      if (_readu32 (fd, filename, &patch->relocs[i]) < 0)
	return -1;
    }
  return 0;
}


static int
read_symbols_data (int fd, const char *filename, struct patch *patch)
{
  size_t i;
  if (_readu16 (fd, filename, &patch->numsymbols) < 0)
    return -1;
  patch->symbols = _zalloc (sizeof (struct symbol) * patch->numsymbols);
  for (i = 0; i < patch->numsymbols; i++)
    {
      struct symbol *sym = &patch->symbols[i];
      uint16_t size;
      if (_readu16 (fd, filename, &size) < 0)
	return -1;

      sym->name = _zalloc (size + 1);
      if (_read (fd, filename, sym->name, size) < 0)
	return 0;

      if (_readu16 (fd, filename, &size) < 0)
	return -1;

      sym->section = _zalloc (size + 1);
      if (_read (fd, filename, sym->section, size) < 0)
	return 0;

      if (_readu32 (fd, filename, &sym->sec_off) < 0)
	return -1;
      if (_readu32 (fd, filename, &sym->sym_off) < 0)
	return -1;
    }
  return 0;
}


static int
read_ex_table_entries (int fd, const char *filename, struct patch *patch)
{
  size_t i;

  if (_readu16 (fd, filename, &patch->numexctblents) < 0)
    return -1;

  patch->exctblents = _zalloc (sizeof (struct exctbl_entry) *
			       patch->numexctblents);

  for (i = 0; i < patch->numexctblents; i++)
    {
      struct exctbl_entry *ete = &patch->exctblents[i];

      if (_readu32 (fd, filename, &ete->addrrel) < 0)
	return -1;
      if (_readu32 (fd, filename, &ete->contrel) < 0)
	return -1;
    }

  if (_readu16 (fd, filename, &patch->numpreexctblents) < 0)
    return -1;

  patch->preexctblents = _zalloc (sizeof (struct exctbl_entry) *
				  patch->numpreexctblents);

  for (i = 0; i < patch->numpreexctblents; i++)
    {
      struct exctbl_entry *ete = &patch->preexctblents[i];

      if (_readu32 (fd, filename, &ete->addrrel) < 0)
	return -1;
      if (_readu32 (fd, filename, &ete->contrel) < 0)
	return -1;
    }

  return 0;
}


static int
_load_patch_file3 (int fd, const char *filename, struct patch *patch)
{
  if (extract_sha1_from_patch (patch->sha1, sizeof (patch->sha1),
			       fd, filename) < 0)
    return -1;

  /* Calculate SHA1 hash and verify it matches filename */
  unsigned char hash[SHA_DIGEST_LENGTH];
  off_t file_size = calc_file_size (fd, filename);
  if (calc_block_sha1 (fd, filename, 0,
		       file_size - (SHA_DIGEST_LENGTH), hash) < 0)
    return -1;

  if (memcmp (patch->sha1, hash, sizeof (patch->sha1)) != 0)
    {
      char hex[SHA_DIGEST_LENGTH * 2 + 1];
      fprintf (stderr, "%s: hash mismatch\n", filename);
      bin2hex (hash, sizeof (hash), hex, sizeof (hex));
      fprintf (stderr, "  calculated %s\n", hex);
      return -1;
    }

  lseek (fd, XSPATCH_COOKIE_LEN, SEEK_SET);

  if (read_tag_data (fd, filename, patch) < 0)
    return -1;

  if (read_refxen_data (fd, filename, patch) < 0)
    return -1;

  if (read_deps_data (fd, filename, patch) < 0)
    return -1;

  /* Only used for crowbar, ignored in this utility */
  if (_readu64 (fd, filename, &patch->crowbarabs) < 0)
    return -1;

  /* Virtual address used for first-stage relocation */
  if (_readu64 (fd, filename, &patch->refabs) < 0)
    return -1;

  if (read_blob_data (fd, filename, patch) < 0)
    return -1;

  if (read_reloc_data3 (fd, filename, patch) < 0)
    return -1;

  if (read_check_data (fd, filename, patch) < 0)
    return -1;

  if (read_symbols_data (fd, filename, patch) < 0)
    return -1;

  if (read_func_data (fd, filename, patch) < 0)
    return -1;

  if (read_table_data (fd, filename, patch) < 0)
    return -1;

  return 0;
}


static int
_load_patch_file4 (int fd, const char *filename, struct patch *patch)
{
  if (extract_sha1_from_patch (patch->sha1, sizeof (patch->sha1),
			       fd, filename) < 0)
    return -1;

  /* Calculate SHA1 hash and verify it matches filename */
  unsigned char hash[SHA_DIGEST_LENGTH];
  off_t file_size = calc_file_size (fd, filename);
  if (calc_block_sha1 (fd, filename, 0,
		       file_size - (SHA_DIGEST_LENGTH), hash) < 0)
    return -1;

  if (memcmp (patch->sha1, hash, sizeof (patch->sha1)) != 0)
    {
      char hex[SHA_DIGEST_LENGTH * 2 + 1];
      fprintf (stderr, "%s: hash mismatch\n", filename);
      bin2hex (hash, sizeof (hash), hex, sizeof (hex));
      fprintf (stderr, "  calculated %s\n", hex);
      return -1;
    }

  lseek (fd, XSPATCH_COOKIE_LEN, SEEK_SET);

  if (read_tag_data (fd, filename, patch) < 0)
    return -1;

  if (read_refxen_data (fd, filename, patch) < 0)
    return -1;

  if (read_deps_data (fd, filename, patch) < 0)
    return -1;

  /* Virtual address used for first-stage relocation */
  if (_readu64 (fd, filename, &patch->refabs) < 0)
    return -1;

  if (read_blob_data (fd, filename, patch) < 0)
    return -1;

  if (read_reloc_data3 (fd, filename, patch) < 0)
    return -1;

  if (read_check_data (fd, filename, patch) < 0)
    return -1;

  if (read_symbols_data (fd, filename, patch) < 0)
    return -1;

  if (read_func_data (fd, filename, patch) < 0)
    return -1;

  if (read_table_data (fd, filename, patch) < 0)
    return -1;

  if (read_ex_table_entries (fd, filename, patch) < 0)
    return -1;

  return 0;
}


int
load_patch_file (int fd, const char *filename, struct patch *patch)
{
  patch->version = get_patch_version (fd, filename);

  if (patch->version < 3)
    {
      patch->numdeps = 0;
      patch->numrelocs3 = 0;
      patch->numsymbols = 0;
      patch->tags = "";
    }
  if (patch->version < 4)
    {
      patch->numexctblents = 0;
      patch->numpreexctblents = 0;
    }
  if (patch->version >= 4)
    patch->crowbarabs = 0;

  switch (patch->version)
    {
    case XSPATCH_VER2:
      return _load_patch_file2 (fd, filename, patch);
    case XSPATCH_VER3:
      return _load_patch_file3 (fd, filename, patch);
    case XSPATCH_VER4:
      return _load_patch_file4 (fd, filename, patch);
    default:
      fprintf (stderr, "%s: invalid signature\n", filename);
      return -1;
    }
}


void
print_patch_file_info (struct patch *patch)
{
  size_t i;
  char hex[SHA_DIGEST_LENGTH * 2 + 1];
  bin2hex (patch->sha1, SHA_DIGEST_LENGTH, hex, sizeof (hex));
  printf ("Patch (v%d) Applies To:\n", patch->version);
  printf ("  Hypervisor Version: %s\n", patch->xenversion);
  printf ("  Hypervisor Compile Date: %s\n", patch->xencompiledate);
  printf ("  Patch sha1: %s\n", hex);
  if (patch->version > 2)
    printf ("  Tags: %s\n", patch->tags);
  if (patch->numdeps > 0)
    printf ("Dependencies:\n");
  for (i = 0; i < patch->numdeps; i++)
    {
      struct dependency *dep = &patch->deps[i];
      bin2hex (dep->sha1, SHA_DIGEST_LENGTH, hex, sizeof (hex));
      printf ("  patch: %s @ %llx\n", hex,
	      (long long unsigned int) dep->refabs);
    }
  printf ("\n");

  if (patch->crowbarabs)
    printf ("Crowbar patch\n\n");

  for (i = 0; i < patch->numfuncs; i++)
    {
      struct function_patch *func = &patch->funcs[i];

      printf ("Patch function %s @ %llx\n", func->funcname,
	      (long long unsigned int) func->oldabs);
    }

  for (i = 0; i < patch->numtables; i++)
    {
      struct table_patch *table = &patch->tables[i];

      printf ("Patch table %s @ %llx\n", table->tablename,
	      (long long unsigned int) table->hvabs);
    }

  if (patch->numsymbols > 0)
    printf ("Blob symbols:\n");
  for (i = 0; i < patch->numsymbols; i++)
    {
      struct symbol *sym = &patch->symbols[i];

      printf ("  %s @ %x\n", sym->name, sym->sec_off + sym->sym_off);
    }
}


void
print_json_patch_info (struct patch *patch)
{
  size_t i;
  char hex[SHA_DIGEST_LENGTH * 2 + 1];
  bin2hex (patch->sha1, SHA_DIGEST_LENGTH, hex, sizeof (hex));
  printf ("{\n");
  printf ("  \"version\": %d,\n", patch->version);
  printf ("  \"sha1\": \"%s\",\n", hex);
  printf ("  \"xen_version\": \"%s\",\n", patch->xenversion);
  printf ("  \"xen_compile_date\": \"%s\",\n", patch->xencompiledate);
  printf ("  \"tags\": \"%s\",\n", patch->tags);
  printf ("  \"dependencies\": [\n");
  for (i = 0; i < patch->numdeps; i++)
    {
      struct dependency *dep = &patch->deps[i];
      bin2hex (dep->sha1, SHA_DIGEST_LENGTH, hex, sizeof (hex));
      printf ("    {\"sha1\": \"%s\", \"refabs\": \"0x%llx\"}",
	      hex, (long long unsigned int) dep->refabs);
      printf ("%s\n", ((i == patch->numdeps - 1) ? "" : ","));
    }
  printf ("  ],\n");
  printf ("  \"crowbar\": %s,\n", ((patch->crowbarabs) ? "true" : "false"));
  printf ("  \"functions\": [\n");
  for (i = 0; i < patch->numfuncs; i++)
    {
      struct function_patch *func = &patch->funcs[i];
      printf ("    {\"name\": \"%s\", \"addr\": \"0x%llx\"}",
	      func->funcname, (long long unsigned int) func->oldabs);
      printf ("%s\n", ((i == patch->numfuncs - 1) ? "" : ","));
    }
  printf ("  ],\n");
  printf ("  \"tables\": [\n");
  for (i = 0; i < patch->numtables; i++)
    {
      struct table_patch *table = &patch->tables[i];
      printf ("    {\"name\": \"%s\", \"addr\": \"0x%llx\"}",
	      table->tablename, (long long unsigned int) table->hvabs);
      printf ("%s\n", ((i == patch->numtables - 1) ? "" : ","));
    }
  printf ("  ],\n");
  printf ("  \"symbols\": [\n");
  for (i = 0; i < patch->numsymbols; i++)
    {
      struct symbol *sym = &patch->symbols[i];
      printf ("    {\"name\": \"%s\", \"offset\": \"0x%x\"}",
	      sym->name, sym->sec_off + sym->sym_off);
      printf ("%s\n", ((i == patch->numsymbols - 1) ? "" : ","));
    }
  printf ("  ]\n");
  printf ("}\n");
}
