BUILD_ROOT := "/home/mdday/src/sandbox/"
CFLAGS =  -g -Wall -fPIC -std=gnu11  -mcmodel=large

LIB_FILES=libsandbox.o hexdump.o sandbox-listen.o

sandbox: sandbox.o libsandbox.a
	$(CC) $(CFLAGS) -o sandbox sandbox.o libsandbox.a 

libsandbox.a: libsandbox.o hexdump.o sandbox-listen.o gitsha
	ar cr libsandbox.a libsandbox.o hexdump.o sandbox-listen.o

.PHONY: gitsha
gitsha: gitsha.txt libsandbox.o
	$(shell objcopy --add-section .buildinfo=gitsha.txt --set-section-flags .build=noload,readonly libsandbox.o libsandbox.o)

libsandbox.o: libsandbox.c sandbox.h sandbox-listen.c gitsha.txt

gitsha.txt: .git/HEAD .git/index
	echo -n "SANDBOXBUILDINFOSTART" > $@
	echo -n "{" >> $@
	echo -n "'git-revision': '$(shell git rev-parse HEAD)'," >> $@	
	echo -n "'compiled': '$(shell $(CC) --version)'," >> $@
	echo -n "'ccflags': '$(CFLAGS)'," >> $@
	echo -n "'compile-date': '$(shell date)'" >> $@
	echo  "}" >> $@
	echo -n "SANDBOXBUILDINFOEND" >> $@

*.c: platform.h

platform.h:
	$(shell $(BUILD_ROOT)config.sh)


.PHONY: clean
clean:
	-rm -v $(BUILD_ROOT)sandbox
	-rm -v $(BUILD_ROOT)/*a
	-rm -v $(BUILD_ROOT)/*o
	-rm -v gitsha.txt
	-rm -v platform.h




.PHONY: shared
shared: clean libsandbox.so

libsandbox.so: $(LIB_FILES) gitsha
	$(CC) -fPIC -shared -o $@ $(LIB_FILES)

.PHONY: static
static: clean libsandbox.a

.PHONY: all
all: static shared sandbox

.PHONY: install
install:
	cp -v libsandbox.a /usr/lib64/
	cp -v sandbox.h /usr/include/


.PHONY: qemu
qemu:
	cp -v  libsandbox.c ~/src/qemu/target-i386/libsandbox.c
	cp -v  sandbox.h ~/src/qemu/include/qemu/sandbox.h

