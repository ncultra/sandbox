#!/bin/bash
cpp -dM sandbox.h | grep SANDBOX > sandbox_decls.h
gcc -g -o sandbox sandbox.c sandbox.S
