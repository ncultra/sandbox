BUILD_ROOT := "/home/$(shell id -n -u)/src/sandbox/"
CC	:= gcc
CFLAGS = -D sandbox_port -g  -Wall -Werror -fPIC -std=gnu11 -ffunction-sections -fdata-sections -fkeep-static-consts -fno-inline  -fms-extensions -pthread

ifndef BUILD_COMMENT
	BUILD_COMMENT=""
else

endif

MAJOR_VERSION=0
MINOR_VERSION=0
REVISION=1
LIB_FILES=libsandbox.o  sandbox-listen.o
CLEAN=rm -f sandbox.out  *.o *.a *.so gitsha.txt platform.h \
	gitsha.h version.mak

# this uses the qemu version file
.PHONY: version.mak
version.mak:
	bash config.sh --ver="../VERSION"

include version.mak

.PHONY: gitsha
gitsha: gitsha.txt gitsha.h libsandbox.o
#	$(shell objcopy --add-section .buildinfo=gitsha.txt --set-section-flags .build=nolo#ad,readonly libsandbox.o libsandbox.o)

# any target that requires libsandbox will pull in gitsha.txt automatically
libsandbox.a: gitsha.txt libsandbox.o  sandbox-listen.o
	$(shell objcopy --add-section .buildinfo=gitsha.txt \
	--set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)
# add the static elf library to the sandbox
	ar cr libsandbox.a libsandbox.o  sandbox-listen.o

# force the qemu makefile to copy the build info into the .buidinfo section
.PHONY: libsandbox-qemu
libsandbox-qemu: libsandbox.o sandbox-listen.o version.mak
	$(shell objcopy --add-section .buildinfo=gitsha.txt \
	--set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)

libsandbox.o: libsandbox.c platform.h sandbox.h gitsha.h gitsha.txt
	$(CC) $(CFLAGS) -c -O0 $<
	$(shell sh config.sh)

sandbox-listen.o: sandbox-listen.c platform.h gitsha
	$(CC)  $(CFLAGS) -c -O0  $<
	$(shell sh config.sh)

.PHONY: clean
clean:
	$(shell $(CLEAN) &> /dev/null)
	cd user && make $@ > /dev/null
	@echo "repo is clean"

*.c: platform.h

platform.h:
	$(shell sh config.sh)

.PHONY: raxlpxs
raxlpxs: platform.h
	cd user && make $@


.PHONY: gitsha.txt
gitsha.txt: version.mak
	@echo -n "SANDBOXBUILDINFOSTART" > $@
	@echo -n "{" >> $@
	@echo -n "'git-revision': \"$(GIT_REVISION)\"," >> $@
	@echo -n "'compiled': \"`gcc --version`\"," >> $@
	@echo -n "'ccflags': \"$(CFLAGS)\"," >> $@
	@echo -n "'compile-date': \"`date`\"," >> $@
	@echo -n "'version':\"$(VERSION_STRING)\"," >> $@
	@echo -n "'major':\"$(MAJOR_VERSION)\"," >> $@
	@echo -n "'minor':\"$(MINOR_VERSION)\"," >> $@
	@echo -n "'revision':\"$(REVISION)\"," >> $@
	@echo -n "'comment':\"$(BUILD_COMMENT)\"," >> $@
	@echo -n "}" >> $@
	@echo -n "SANDBOXBUILDINFOEND" >> $@

.PHONY: gitsha.h

gitsha.h: version.mak
	@echo "/* this file is generated automatically in the Makefile */" >$@
	@echo "const char *git_revision = \"$(GIT_REVISION)\";" >> $@
	@echo "const char *compiled = \""`gcc --version`"\";" >> $@
	@echo "const char *ccflags = \"$(CFLAGS)\";" >> $@
	@echo "const char *compile_date = \"`date`\";" >> $@
	@echo "const int major = $(MAJOR_VERSION);" >> $@
	@echo "const int minor = $(MINOR_VERSION);" >> $@
	@echo "const int revision = $(REVISION);" >> $@
	@echo "const char *comment = \"$(BUILD_COMMENT)\";" >> $@

	@echo "const char *get_git_revision(void){return git_revision;}" >> $@
	@echo "const char *get_compiled(void){return compiled;}" >> $@
	@echo "const char *get_ccflags(void){return ccflags;}" >> $@
	@echo "const char *get_compiled_date(void){return compile_date;}" >> $@
	@echo "int get_major(void){return major;}" >> $@
	@echo "int get_minor(void){return minor;}" >> $@
	@echo "int get_revision(void){return revision;}" >> $@
	@echo "const char *get_comment(void){return comment;}" >> $@	


.PHONY: static
static: libsandbox.a

.PHONY: all
all:
	make static
	cd user && make raxlpxs
