BUILD_ROOT := "/home/mdday/src/sandbox/"
CFLAGS =  -g -Wall -std=gnu11


sandbox: sandbox.o sandbox.h libsandbox.a
	$(CC) $(CFLAGS) -static -c sandbox.c -llibsandbox.a
	$(CC) $(CFLAGS) -o sandbox sandbox.o libsandbox.a 

libsandbox.a: libsandbox.o hexdump.o gitsha.o
	ar cr libsandbox.a libsandbox.o hexdump.o gitsha.o

libsandbox.o: libsandbox.c  platform.h
	$(CC) $(CFLAGS) -c  libsandbox.c

platform.h: config.sh
	$(BUILD_ROOT)config.sh

hexdump.o: hexdump.c
	$(CC) $(CFLAGS) -c hexdump.c	

gitsha.o: gitsha.c
	$(CC) $(CFLAGS) -c gitsha.c

gitsha.c: .git/HEAD .git/index
	echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > $@	

,PHONY: intsall
install:
	cp -v libsandbox.a /usr/lib64/
	cp -v sandbox.h /usr/include/

.PHOMY: clean
clean:
	rm -v $(BUILD_ROOT)sandbox
	rm -v $(BUILD_ROOT)/*a
	rm -v $(BUILD_ROOT)/*o
	rm -v gitsha.c

.PHONY: qemu
qemu:
	cp -v  libsandbox.c ~/src/qemu/target-i386/libsandbox.c
	cp -v  sandbox.h ~/src/qemu/include/qemu/sandbox.h
# qemu will not build symbolic links
