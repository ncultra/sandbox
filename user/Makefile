SANDBOX_DIR ?= ..
CC	:= gcc
CFLAGS = -g  -Wall -Werror -fPIC -std=gnu11 -ffunction-sections -fdata-sections -fkeep-static-consts -fno-inline  -fms-extensions -pthread -D sandbox_port

MAJOR_VERSION=0
MINOR_VERSION=0
REVISION=1
LIBS=$(SANDBOX_DIR)/libsandbox.a -lz -lcrypto -lelf -lpthread -ldl -lm
EXE=raxlpxs
CLEAN=rm -f $(EXE) *.o *.a *.so 

.PHONY: clean
clean:
	$(shell $(CLEAN) &> /dev/null)	
	@echo "repo is clean"

.PHONY: superclean
superclean: clean
	$(shell rm *~ &> /dev/null)
	@echo "cleaned unwanted backup files"

.PHONY: raxlpxs
raxlpxs: raxlpxs.o patch_file.o util.o portability.o
	$(CC) $(CFLAGS) -o raxlpxs raxlpxs.o patch_file.o util.o portability.o $(LIBS)
