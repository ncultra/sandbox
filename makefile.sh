#!/bin/bash
cpp -dM sandbox.h | grep -iE 'SANDBOX|PATCH|PLATFORM' | grep -v GNU > sandbox_decls.h
gcc -g -o sandbox sandbox.c sandbox.S
