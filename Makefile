# start using a makefile ..



sandbox: sandbox.o sandbox.h libsandbox.a
	$(CC) -g -static -c sandbox.c -llibsandbox.a
	gcc -o sandbox sandbox.o libsandbox.a 

libsandbox.a: libsandbox.o
	ar cr libsandbox.a libsandbox.o

libsandbox.o: libsandbox.c
	gcc -c -g libsandbox.c

