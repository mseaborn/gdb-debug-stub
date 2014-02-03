#!/bin/bash
# Copyright (c) 2012 Google Inc. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -eux

gcc -Wall -m32 -g stub.c -o stub_32
gcc -Wall -m64 -g stub.c -o stub_64
