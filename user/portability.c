/***************************************************************
 * Sandbox allows a user-space process to live-patch itself.
 * Patches are placed in the "sandbox," which is a area in the
 * .text segment
 *
 * Copyright 2015-16 Rackspace, Inc.
 ***************************************************************/
#include <math.h>
#include "../sandbox.h"
#include "portability.h"

int __attribute__ ((deprecated))
copy_from_guest (void *dest, XEN_GUEST_HANDLE (int) fd, int size)
{
  return readn (fd, dest, (size_t) size);
}

int __attribute__ ((deprecated))
copy_to_guest (XEN_GUEST_HANDLE (int) fd, void *src, int size)
{
  return writen (fd, src, (size_t) size);
}

static char sockname[PATH_MAX];
int sockfd;

/*******************************************************************
 * sandbox_name, AKA sockname, defines the path to the domain socket
 * that provides the other end of the live patching interface.
 * each QEMU instance will have a unique sandbox_name comprised of
 * the path to the socket, and the owners process id
 ******************************************************************/

char *
get_sandbox_name (void)
{
  return strdup (sockname);

}

void
set_sandbox_name (char *name)
{
  strncpy (sockname, name, PATH_MAX);
}


/* use a wrapper function so we can eventually support other media beyond */
/* a domain socket, eg sysfs file */
int
connect_to_sandbox (char *sandbox_name)
{
  return client_func (sandbox_name);
}

int
open_xc (xc_interface_t * xch)
{

  if (sockfd <= 0)
    {
      sockfd = connect_to_sandbox (sockname);
    }

  *xch = sockfd;
  if (sockfd < 0)
    {
      printf ("xc_interface_open failed\n");
      return -1;
    }
  return 0;
}

/* return: < 0 SANDBOX_ERR for error; */
/* zero (SANDBOX_OK) if patch not applied; one (SANDBOX_SUCCESS) if patch applied */
/* if sha1 is NULL return all applied patches
 * return an array of xenlp_patch_info structs
 *
 * no reason to support iterative searching, there is no upper limit to how
 * many patches we can return in a hypercall, we are using a socket instead
 */

/* TODO: pass a hex string with the sha1 hash, run bin2hex on the response list, * compare hex strings to find a match
 */
int
__find_patch (int fd, uint8_t sha1[20], struct xenlp_list3 *list)
{
  uint32_t *count = NULL, ccode = SANDBOX_OK;	/* 0 */
  struct xenlp_patch_info3 *response;
  char *rbuf = NULL;

  if (list == NULL)
    {
      DMSG ("__find_patch called with null list\n");
      return SANDBOX_ERR;
    }

  count = (uint32_t *) sandbox_list_patches (fd);
  DMSG ("list path response buf %p\n", count);
  if (count == NULL)
    {
      DMSG ("sandbox_list_patches returned a NULL address\n");
      return SANDBOX_ERR;
    }
  dump_sandbox (count, 32);

  if (*count == 0)
    {
      LMSG ("currently there are no applied patches\n");
      /* ccode = 0; ccode is already set to zero here */
      list->numpatches = 0;
      goto exit;
    }

  DMSG ("%d applied patches...\n", *count);
  rbuf = (char *) count;
  rbuf += sizeof (uint32_t);

  response = (struct xenlp_patch_info3 *) rbuf;
  dump_sandbox (response, 32);
  int return_list_size = __min (*count, MAX_LIST_PATCHES);
  if (sha1 == NULL)
    {				/* this is a list, not a find */
      if (return_list_size < *count)
	{
	  LMSG ("list of %d applied patches exceeds the API support\n",
		*count);
	  LMSG ("returning a truncated list of %d patches\n",
		MAX_LIST_PATCHES);
	  LMSG ("try searching for a specific patch\n");
	}
      memcpy (&list->patches[0], response,
	      return_list_size * sizeof (struct xenlp_patch_info3));
      list->numpatches = return_list_size;
      LMSG ("returning a list of %d applied patches\n", return_list_size);
      ccode = SANDBOX_SUCCESS;
      goto exit;
    }
  else
    {				/* this is a search, not a list */
      for (int i = 0; return_list_size > 0; return_list_size--, i++)
	{
	  if (memcmp (sha1, response[i].sha1, 20) == 0)
	    {
	      memcpy (&list->patches[0], &response[i],
		      sizeof (struct xenlp_patch_info3));
	      list->numpatches = 1;
	      ccode = list->numpatches;
	      LMSG ("one matching applied patch\n");
	      goto exit;
	    }
	}
      /* ccode is already 0. if not, set it to zero here */
      /* ccode = SANDBOX_OK */
      list->numpatches = 0;
      LMSG ("no matching applied live patches\n");
    }

exit:
  free (count);
  return ccode;
}


/* return SANDBOX_OK for success, SANDBOX_ERR on failure */
/* TODO: change sha1 to a hex string, pass to __find_patch as the sha1 */
/* convert bin sha1 to hex before comparing. uses more space but more reliable
 * than converting strings of varying length and format.
 */

int
find_patch (xc_interface_t xch, unsigned char *sha1, size_t sha1_size,
	    struct xenlp_patch_info3 **patch)
{
  int ccode;
  struct xenlp_list3 list;
  if (!patch)
    {
      DMSG ("must provide an output buffer ptr to find_patch\n");
      return SANDBOX_ERR;
    }
  ccode = __find_patch ((int) xch, sha1, &list);
  if (ccode < 0)
    {
      DMSG ("error %d returned by __find_patch\n", ccode);
      return SANDBOX_ERR;
    }
  if (ccode == 0)
    {				/* returned an empty list */
      if (*patch)
	{
	  free (*patch);
	  (*patch = NULL);
	}

    }
  else
    {				/* ccode is 1, found the patch */
      *patch = realloc (*patch,
			list.numpatches * sizeof (struct xenlp_patch_info3));
      if (*patch == NULL)
	{
	  DMSG ("unable to allocate memory in find_patch\n");
	  return SANDBOX_ERR;
	}
      memcpy (*patch, &list.patches[0],
	      list.numpatches * sizeof (struct xenlp_patch_info3));
    }

  return ccode;

}


int __attribute__ ((deprecated))
__do_lp_list (xc_interface_t xch, struct xenlp_list3 *list)
{
  if (list == NULL)
    {
      DMSG ("error bad list parameter to do_lp_list\n");
      return SANDBOX_ERR;
    }

  return __find_patch ((int) xch, NULL, (struct xenlp_list3 *) list);
}


int
__do_lp_list3 (xc_interface_t xch, struct xenlp_list3 *list)
{
  if (list == NULL)
    {
      DMSG ("error bad list parameter to do_lp_list\n");
      return SANDBOX_ERR;
    }

  return __find_patch ((int) xch, NULL, list);
}


int
__do_lp_caps (xc_interface_t xch, struct xenlp_caps *caps)
{
  caps->flags |= XENLP_CAPS_V3 | XENLP_CAPS_APPLY4;

  return 0;
}


int __attribute__ ((deprecated))
__do_lp_apply (xc_interface_t xch, void *buf, size_t buflen)
{
  return 0;
}



/*
  client: ->
  cmd_apply
  ---_cmd_apply3
  -----fill_patch_buf
  ---------__do_lp_apply3
  ---------------do_lp_apply
  ------------------send_rr_buf

  server: ->
  dispatch_apply
  ---xenlp_apply3
  ---send_rr_buf

  client:
  ------read_sandbox_message_header
  ---------dispatch_apply_response
  <----------------------|
*/

int
__do_lp_apply3 (xc_interface_t xch, void *buf, size_t buflen)
{
    return __do_lp_apply4(xch, buf, buflen);
    
}

int
__do_lp_apply4 (xc_interface_t xch, void *buf, size_t buflen)
{
    /* fill buffer, write it to the socket  */
    int ccode = SANDBOX_ERR;
    void *buf2 = NULL;
    uint16_t version = 1, id = SANDBOX_MSG_APPLYRSP;
    uint32_t len = 0;

    if (send_rr_buf ((int) xch,
                     SANDBOX_MSG_APPLY,
                     buflen, buf, SANDBOX_LAST_ARG) == SANDBOX_OK)
    {
        ccode =
            read_sandbox_message_header ((int) xch, &version, &id, &len, &buf2);
        if (buf2 != NULL)
            free (buf2);
    }
    return ccode;
}

/*
  client: -> __do_lp_undo3
  ------send_rr_buf

  server: -> dispatch_undo_req
  --- do_lp_undo3
  ------send_rr_buf

  client:
  ------read_sandbox_message_header
  ---------dispatch_undo_rep
  <----------------------|

*/
/* buf is a ptr to sha1, buflen = 20 bytes */
int
__do_lp_undo3 (xc_interface_t xch, void *buf, size_t buflen)
{
  uint16_t version, id;
  uint32_t len, ccode = SANDBOX_ERR;
  char *sha1_buf = NULL;

  /* when including var args, have to also pass the buf size */
  if (send_rr_buf
      (xch, SANDBOX_MSG_UNDO_REQ, buflen, buf,
       SANDBOX_LAST_ARG) == SANDBOX_OK)
    {
      ccode =
	read_sandbox_message_header (xch, &version, &id, &len,
				     (void **) &sha1_buf);
    }

  return ccode;
}

int
get_info_strings (int fd, int display)
{
  char *info_buf, *info_buf_save, *p;
  int index = 0;

  if (fd < 0)
    {
      DMSG ("get_info was passed a bad socket\n");
      return SANDBOX_ERR_BAD_FD;
    }

  info_buf = get_sandbox_build_info (fd);
  if (info_buf == NULL)
    {
      LMSG ("unable to get info strings\n");
      return SANDBOX_ERR_RW;
    }

  /* split the long string into separate strings */
  p = strtok_r (info_buf, "\n", &info_buf_save);
  for (index = 0; index < COUNT_INFO_STRINGS && p != NULL; index++)
    {
      strncpy (info_strings[index], p, INFO_STRING_LEN);
      if (display)
	LMSG ("%s\n", info_strings[index]);
      p = strtok_r (NULL, "\n", &info_buf_save);
    }
  if (index < COUNT_INFO_STRINGS - 1)
    {
      LMSG ("error parsing info strings, index: %d\n", index);
      return SANDBOX_ERR_PARSE;
    }
  free (info_buf);
  return SANDBOX_OK;
}
