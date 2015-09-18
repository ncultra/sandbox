#!/bin/bash
cpp -dM sandbox.h | grep -iE 'SANDBOX|PATCH|PLATFORM' | grep -v GNU
gcc -g -o sandbox sandbox.c sandbox.S
