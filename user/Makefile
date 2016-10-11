BUILD_ROOT := "/home/$(shell id -n -u)/src/sandbox/user"
CC	:= gcc
CFLAGS = -g  -Wall -Werror -fPIC -ffunction-sections -fdata-sections -fkeep-static-consts -fkeep-inline-functions -pthread
MAJOR_VERSION=0
MINOR_VERSION=0
REVISION=1

CLEAN=rm -f raxlpxs*.o *.a *.soi


.PHONY raxlpxs
raxlpxs: patch_file.c patch_file.c util.c util.h raxlpxs.c raxlpxs.h
		$(CC) $(CFLAGS) -o raxlpxs raxlpxs.o patch_file.o util.o
