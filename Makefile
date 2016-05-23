BUILD_ROOT := "/home/mdday/src/sandbox/"
CFLAGS =  -g -Wall -fPIC -std=gnu11 -mcmodel=large -ffunction-sections -pthread
MAJOR_VERSION=0
MINOR_VERSION=0
REVISION=1
LIB_FILES=libsandbox.o  sandbox-listen.o
LIBELF=/usr/lib64/libelf.a
CLEAN=@-rm -f sandbox raxlpqemu *o *a *so gitsha.txt platform.h \
	gitsha.h &>/dev/null

.PHONY: gitsha
gitsha: gitsha.txt gitsha.h libsandbox.o
	$(shell objcopy --add-section .buildinfo=gitsha.txt --set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)

sandbox: sandbox.o libsandbox.a
	$(CC) $(CFLAGS) -o sandbox sandbox.o libsandbox.a 

# any target that requires libsandbox will pull in gitsha.txt automatically
libsandbox.a: gitsha.txt libsandbox.o  sandbox-listen.o
	$(shell objcopy --add-section .buildinfo=gitsha.txt \
	--set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)
# add the static elf library to the sandbox
	ar cr libsandbox.a libsandbox.o  sandbox-listen.o \
	$(LIBELF)

libsandbox.o: libsandbox.c sandbox.h sandbox-listen.c gitsha.h
	$(CC) -g -c -Wall  -std=gnu11 -mcmodel=large \
	 -ffunction-sections -fkeep-static-consts -O0 -pthread $<
.PHONY: qclean
clean:	
	$(CLEAN)
	@echo "repo is clean"

*.c: platform.h

platform.h:
	$(shell $(BUILD_ROOT)config.sh)

.PHONY: raxlpqemu
raxlpqemu: raxlpqemu.o util.o libsandbox.a platform.h
	$(CC) $(CFLAGS) -c raxlpqemu.c util.c
#TODO: might need to link libraries statically (probably not)
	$(CC) $(CFLAGS) -o raxlpqemu -lz -lelf -lcrypto -lpthread -ldl raxlpqemu.o util.o libsandbox.a

.PHONY: gitsha.txt

# use the git tag as the version number
# tag should be in the format v0.0.0
gitsha.txt:
	@echo  "generating .buildinfo elf section..."
	@echo -n "SANDBOXBUILDINFOSTART" > $@
	@echo -n "{" >> $@
	@echo -n "'git-revision': '$(shell git rev-parse HEAD)'," >> $@	
	@echo -n "'compiled': '$(shell $(CC) --version)'," >> $@
	@echo -n "'ccflags': '$(CFLAGS)'," >> $@
	@echo -n "'compile-date': '$(shell date)'," >> $@
	@echo -n "'tag': '$(shell git describe --abbrev=0 --tags)'" >> $@
	@echo  "}" >> $@
	@echo -n "SANDBOXBUILDINFOEND" >> $@

.PHONY: gitsha.h

gitsha.h:
	@echo "generating gitsha.h...."
	@echo "/* this file is generated automatically in the Makefile */" >$@
	@echo "const char *git_revision=\"$(shell git rev-parse HEAD)\";" >> $@
	@echo "const char *compiled=\"$(shell $(CC) --version)\";" >> $@
	@echo "const char *ccflags=\"$(CFLAGS)\";" >> $@
	@echo "const char *compile_date=\"$(shell date)\";" >> $@
	@echo "const char *tag=\"$(shell git describe --abbrev=0 --tags)\";" >> $@
	@echo "const int major = $(MAJOR_VERSION);" >> $@
	@echo "const int minor = $(MINOR_VERSION);" >> $@
	@echo "const int revision = $(REVISION);" >> $@
	@echo "static inline const char *get_git_revision(void){return git_revision;}" >> $@
	@echo "static inline const char *get_compiled(void){return compiled;}" >> $@
	@echo "static inline const char *get_ccflags(void){return ccflags;}" >> $@
	@echo "static inline const char *get_compiled_date(void){return compile_date;}" >> $@
	@echo "static inline const char *get_tag(void){return tag;}" >> $@
	@echo "static inline const int get_major(void){return major;}" >> $@
	@echo "static inline const int get_minor(void){return minor;}" >> $@
	@echo "static inline const int get_revision(void){return revision;}" >> $@

.PHONY: shared
shared: libsandbox.so

libsandbox.so: gitsha $(LIB_FILES)
	$(CC) -fPIC -shared -o $@ $(LIB_FILES)
	$(shell objcopy --add-section .buildinfo=gitsha.txt --set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)


.PHONY: static
static: libsandbox.a

.PHONY: all
all: static  sandbox raxlpqemu

.PHONY: install
install:
	cp -v libsandbox.a /usr/lib64/
	cp -v sandbox.h /usr/include/


.PHONY: qemu
qemu:
	cp -v  libsandbox.c ~/src/qemu/target-i386/libsandbox.c
	cp -v  sandbox.h ~/src/qemu/include/qemu/sandbox.h

