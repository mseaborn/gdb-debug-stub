#!/bin/bash

set -eux

gcc -Wall -m32 -g stub.c -o stub_32
gcc -Wall -m64 -g stub.c -o stub_64
