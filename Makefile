BUILD_ROOT := "/home/mdday/src/sandbox/"



sandbox: sandbox.o sandbox.h libsandbox.a
	$(CC) -g -static -c sandbox.c -llibsandbox.a
	gcc -o sandbox sandbox.o libsandbox.a 

libsandbox.a: libsandbox.o
	ar cr libsandbox.a libsandbox.o

libsandbox.o: libsandbox.c
	gcc -c -g libsandbox.c


,PHONY: intsall
install:
	cp -v libsandbox.a /usr/lib64/
	cp -v sandbox.h /usr/include/

.PHOMY: clean
clean:
	rm -v $(BUILD_ROOT)/sandbox
	rm -v $(BUILD_ROOT)/*a
	rm -v $(BUILD_ROOT)/*o

.PHONY: qemu
qemu:
	cp -v  libsandbox.c ~/src/qemu/target-i386/libsandbox.c
	cp -v  sandbox.h ~/src/qemu/include/qemu/sandbox.h
# qemu will not build symbolic links
