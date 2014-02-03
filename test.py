# Copyright (c) 2012 Google Inc. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import re
import subprocess


# Python's line reader does too much buffering.  This implementation
# returns lines as soon as they are read.
def ReadLines(fh):
  data = ''
  while True:
    while '\n' in data:
      lines = data.split('\n')
      for line in lines[:-1]:
        yield line
      data = lines[-1]
      del lines
    data += os.read(fh.fileno(), 1000)
    if data == '':
      return


def GetConsoleLines(lines):
  got = []
  for line in lines:
    if line.startswith('~'):
      assert line.startswith('~"')
      assert line.endswith('\\n"')
      got.append(line[2:-3])
  return got


def AssertEq(x, y):
  if x != y:
    raise AssertionError('%r != %r' % (x, y))


def TestStub(prog):
  proc2 = subprocess.Popen([prog],
                           stderr=open(os.devnull, 'w'))
  proc1 = subprocess.Popen(['gdb', '--interpreter', 'mi', prog],
                           stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE)
  gdb_output = ReadLines(proc1.stdout)
  try:
    def DoCommand(cmd):
      proc1.stdin.write(cmd + '\n')
      got = []
      while True:
        line = gdb_output.next()
        got.append(line)
        #print 'got:', line
        if line.startswith('^'):
          AssertEq(line, '^done')
          return got

    DoCommand('target remote localhost:4014')
    lines = DoCommand('backtrace')
    trace = GetConsoleLines(lines)
    assert re.match(r'#0.*\btest_prog\b', trace[0]), trace[0]
    assert re.match(r'#1.*\bmain\b', trace[1]), trace[1]

    # TODO: Check result
    DoCommand('info registers')

    # 'quit' does not produce a '^' reply, so we do not use
    # DoCommand() for sending it.
    proc1.stdin.write('quit\n')
    #for line in gdb_output:
    #  print 'final:', line
  except:
    proc1.kill()
    proc2.kill()
    raise
  finally:
    proc1.wait()
    proc2.wait()


def Main():
  for prog in ['./stub_32', './stub_64']:
    print 'testing %s...' % prog
    TestStub(prog)
  print 'pass'


if __name__ == '__main__':
  Main()
