#!/bin/bash

set -eux

gcc -Wall -m32 -g stub.c -o stub
./stub
