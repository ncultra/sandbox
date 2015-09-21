# start using a makefile ..

sandbox: sandbox.c sandbox.S sandbox.decls.h sandbox.h
	$(CC) -g -o sandbox sandbox.c sandbox.S

sandbox.decls.h: sandbox.h
	$(CPP) -dM sandbox.h | grep -iE 'SANDBOX|PATCH|PLATFORM' | grep -v GNU > sandbox_decls.h
