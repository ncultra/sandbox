BUILD_ROOT := "/home/mdday/src/sandbox/"
CFLAGS =  -g -Wall -fPIC -std=gnu11 -mcmodel=large -ffunction-sections

LIB_FILES=libsandbox.o hexdump.o sandbox-listen.o gitsha.o
LIBELF=/usr/lib64/libelf.a
CLEAN=@-rm -f sandbox raxlpqemu *o *a *so gitsha.txt platform.h \
	gitsha.h &>/dev/null

.PHONY: gitsha
gitsha: gitsha.txt libsandbox.o
	$(shell objcopy --add-section .buildinfo=gitsha.txt --set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)

sandbox: clean sandbox.o libsandbox.a
	$(CC) $(CFLAGS) -o sandbox sandbox.o libsandbox.a 

# any target that requires libsandbox will pull in gitsha.txt automatically
libsandbox.a: gitsha.txt libsandbox.o hexdump.o sandbox-listen.o
	$(shell objcopy --add-section .buildinfo=gitsha.txt \
	--set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)
# add the static elf library to the sandbox
	ar crT libsandbox.a libsandbox.o hexdump.o sandbox-listen.o \
	$(LIBELF)

libsandbox.o: libsandbox.c sandbox.h sandbox-listen.c gitsha.h

.PHONY: clean
clean:	
	$(CLEAN)
	@echo "repo is clean"

*.c: platform.h

platform.h:
	$(shell $(BUILD_ROOT)config.sh)

.PHONY: raxlpqemu
raxlpqemu: clean raxlpqemu.o util.o libsandbox.a platform.h
	$(CC) $(CFLAGS) -c raxlpqemu.c util.c
#TODO: might need to link libraries statically (probably not)
	$(CC) $(CFLAGS) -o raxlpqemu -lz -lelf -lcrypto -lpthread -ldl raxlpqemu.o util.o libsandbox.a

# use the git tag as the version number
# tag should be in the format v0.0.0
gitsha.txt: .git/HEAD .git/index
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

gitsha.h: .git/HEAD .git/index
	@echo "generating gitsha.h...."
	@echo "/* this file is generated automatically in the Makefile */" >$@
	@echo "const char *git_revision=\"$(shell git rev-parse HEAD)\";" >> $@
	@echo "const char *compiled=\"$(shell $(CC) --version)\";" >> $@
	@echo "const char *ccflags=\"$(CFLAGS)\";" >> $@
	@echo "const char *compile_date=\"$(shell date)\";" >> $@
	@echo "const char *tag=\"$(shell git describe --abbrev=0 --tags)\";" >> $@
	@echo "static inline const char *get_revision(void){return git_revision;}" >> $@
	@echo "static inline const char *get_compiled(void){return compiled;}" >> $@
	@echo "static inline const char *get_ccflags(void){return ccflags;}" >> $@
	@echo "static inline const char *get_compiled_date(void){return compile_date;}" >> $@
	@echo "static inline const char *get_tag(void){return tag;}" >> $@


.PHONY: shared
shared: clean libsandbox.so

libsandbox.so: gitsha.txt $(LIB_FILES)
	$(CC) -fPIC -shared -o $@ $(LIB_FILES)
	$(shell objcopy --add-section .buildinfo=gitsha.txt --set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)


.PHONY: static
static: clean libsandbox.a

.PHONY: all
all: static shared sandbox raxl

.PHONY: install
install:
	cp -v libsandbox.a /usr/lib64/
	cp -v sandbox.h /usr/include/


.PHONY: qemu
qemu:
	cp -v  libsandbox.c ~/src/qemu/target-i386/libsandbox.c
	cp -v  sandbox.h ~/src/qemu/include/qemu/sandbox.h

