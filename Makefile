BUILD_ROOT := "/home/mdday/src/sandbox/"
CFLAGS =  -g -Wall -std=gnu11


sandbox: sandbox.o libsandbox.a
	$(CC) $(CFLAGS) -o sandbox sandbox.o libsandbox.a 

libsandbox.a: libsandbox.o hexdump.o gitsha.o sandbox-listen.o
	ar cr libsandbox.a libsandbox.o hexdump.o gitsha.o sandbox-listen.o

gitsha.c: .git/HEAD .git/index
	echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > $@	
	echo "const char *cc = \"$(shell $(CC) --version)\";" >> $@
	echo "const char *ccflags = \"$(CFLAGS)\";" >> $@

*.c: platform.h

platform.h:
	$(shell $(BUILD_ROOT)config.sh)

.PHONY: install
install:
	cp -v libsandbox.a /usr/lib64/
	cp -v sandbox.h /usr/include/

.PHOMY: clean
clean:
	-rm -v $(BUILD_ROOT)sandbox
	-rm -v $(BUILD_ROOT)/*a
	-rm -v $(BUILD_ROOT)/*o
	-rm -v gitsha.c
	-rm -v platform.h

.PHONY: qemu
qemu:
	cp -v  libsandbox.c ~/src/qemu/target-i386/libsandbox.c
	cp -v  sandbox.h ~/src/qemu/include/qemu/sandbox.h

*.o: *.c
	$(CC) $(CFLAGS) -c $<

