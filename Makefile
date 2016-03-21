BUILD_ROOT := "/home/mdday/src/sandbox/"
CFLAGS =  -g -Wall -fPIC -std=gnu11  -mcmodel=large

LIB_FILES=libsandbox.o hexdump.o sandbox-listen.o

CLEAN=@-rm -f sandbox raxlpqemu *o *a *so gitsha.txt platform.h &>/dev/null

.PHONY: gitsha
gitsha: gitsha.txt libsandbox.o
	$(shell objcopy --add-section .buildinfo=gitsha.txt --set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)

sandbox: clean sandbox.o libsandbox.a
	$(CC) $(CFLAGS) -o sandbox sandbox.o libsandbox.a 

# any target that requires libsandbox will pull in gitsha.txt automatically
libsandbox.a: gitsha.txt libsandbox.o hexdump.o sandbox-listen.o
		$(shell objcopy --add-section .buildinfo=gitsha.txt --set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)
	ar cr libsandbox.a libsandbox.o hexdump.o sandbox-listen.o

libsandbox.o: libsandbox.c sandbox.h sandbox-listen.c 

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
	$(CC) $(CFLAGS) -o raxlpqemu -lz -lelf -lcrypto -lpthread -ldl raxlpqemu.o util.o libsandbox.a

# use the git tag as the version number
# tag should be in the format v0.0.0
gitsha.txt: .git/HEAD .git/index
	echo -n "SANDBOXBUILDINFOSTART" > $@
	echo -n "{" >> $@
	echo -n "'git-revision': '$(shell git rev-parse HEAD)'," >> $@	
	echo -n "'compiled': '$(shell $(CC) --version)'," >> $@
	echo -n "'ccflags': '$(CFLAGS)'," >> $@
	echo -n "'compile-date': '$(shell date)'," >> $@
	echo -n "'tag': '$(shell git describe --abbrev=0 --tags)'" >> $@
	echo  "}" >> $@
	echo -n "SANDBOXBUILDINFOEND" >> $@

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

