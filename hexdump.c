#include <stdio.h>

void
dump_sandbox (const void *data, size_t size)
{
  char ascii[17];
  size_t i, j;
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
