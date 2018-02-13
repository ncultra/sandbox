CC	:= gcc
CFLAGS = -D sandbox_port -g  -Wall -Werror -fPIC -ffunction-sections -fdata-sections -fkeep-static-consts -fno-inline -pthread

ifndef BUILD_COMMENT
	BUILD_COMMENT=""
else

endif

MAJOR_VERSION=0
MINOR_VERSION=0
REVISION=1
LIB_FILES=libsandbox.o  sandbox-listen.o pmparser.o
CLEAN=rm -f sandbox.out  *.o *.a *.so gitsha.txt platform.h \
	gitsha.h version.mak sha1.txt gitsha.h



# this uses the qemu version file
.PHONY: version.mak
version.mak:
	bash config.sh --ver="../VERSION"

include version.mak


# the gitsha target creates  unique information and copies
# it to buildinfo and sha1 sections. programs linking libsandbox.o
# have these sections, which provide a unique build id (sha1)
# and compile information
#
# this target is is a dependency of sandbox-listen.o,
# which forces libsandbox.o to be built, and then copies the
# important information into elf sections of libsandbox.o
.PHONY: gitsha
gitsha: gitsha.txt gitsha.h libsandbox.o
	$(shell objcopy --add-section .note.rackspace.buildinfo=gitsha.txt \
	--set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)
	$(shell objcopy --add-section .note.rackspace.sha1=sha1.txt \
	--set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)

# any target that requires libsandbox will pull in gitsha.txt automatically
libsandbox.a: sha1.txt gitsha.txt libsandbox.o  sandbox-listen.o pmparser.o

# add the static elf library to the sandbox
	ar cr libsandbox.a libsandbox.o  sandbox-listen.o pmparser.o



libsandbox.o: libsandbox.c platform.h sandbox.h gitsha.h gitsha.txt
	$(CC) $(CFLAGS) -c -O0 $<
	$(shell sh config.sh)

sandbox-listen.o: sandbox-listen.c platform.h gitsha
	$(CC)  $(CFLAGS) -c -O0  $<
	$(shell sh config.sh)

pmparser.o: pmparser.c pmparser.h
	$(CC)  $(CFLAGS) -c -O0  $<


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

	@echo -n "{" > $@
	@echo -n "'git-revision': \"$(GIT_REVISION)\"," >> $@
	@echo -n "'compiled': \"`gcc --version`\"," >> $@
	@echo -n "'ccflags': \"$(CFLAGS)\"," >> $@
	@echo -n "'compile-date': \"`date`\"," >> $@
	@echo -n "'version':\"$(VERSION_STRING)\"," >> $@
	@echo -n "'major':\"$(MAJOR_VERSION)\"," >> $@
	@echo -n "'minor':\"$(MINOR_VERSION)\"," >> $@
	@echo -n "'revision':\"$(REVISION)\"," >> $@
	@echo -n "'comment':\"$(BUILD_COMMENT)\"," >> $@
	@echo -n "'uuid': \"`uuid`\"" >> $@	
	@echo -n "}" >> $@

.PHONY: sha1.txt
sha1.txt: gitsha.txt
	sha1sum gitsha.txt | awk '{print $$1}' > sha1.txt


.PHONY: gitsha.h

gitsha.h: version.mak sha1.txt
	@echo "/* this file is generated automatically in the Makefile */" >$@
	@echo "const char *git_revision = \"  $(GIT_REVISION)\";" >> $@
	@echo "const char *compiled = \""`gcc --version`"\";" >> $@
	@echo "const char *ccflags = \"$(CFLAGS)\";" >> $@
	@echo "const char *compile_date = \"`date`\";" >> $@
	@echo "const int major = $(MAJOR_VERSION);" >> $@
	@echo "const int minor = $(MINOR_VERSION);" >> $@
	@echo "const int revision = $(REVISION);" >> $@
	@echo "const char *comment = \"  $(BUILD_COMMENT)  \";" >> $@
	@echo "const char *sha1 = \"$(shell cat sha1.txt)\";" >> $@


	@echo "const char *get_git_revision(void){return git_revision;}" >> $@
	@echo "const char *get_compiled(void){return compiled;}" >> $@
	@echo "const char *get_ccflags(void){return ccflags;}" >> $@
	@echo "const char *get_compiled_date(void){return compile_date;}" >> $@
	@echo "int get_major(void){return major;}" >> $@
	@echo "int get_minor(void){return minor;}" >> $@
	@echo "int get_revision(void){return revision;}" >> $@
	@echo "const char *get_comment(void){return comment;}" >> $@
	@echo "const char *get_sha1(void){return sha1;}" >> $@	

.PHONY: static
static: libsandbox.a

.PHONY: all
all:
	make static
	cd user && make raxlpxs

.PHONY: lint
lint:
	find . -name "*.c"  -exec cppcheck --force {} \;
	find . -name "*.h"  -exec cppcheck --force {} \;

.PHONY: pretty
pretty:
	find . -name "*.c"  -exec indent -gnu {} \;
	find . -name "*.h"  -exec indent -gnu {} \;

.PHONY: scan-build
scan-build:
	scan-build make all
