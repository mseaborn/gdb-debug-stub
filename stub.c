/*
 * Copyright (c) 2012 Google Inc. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>


#define X86_TRAP_FLAG (1 << 8)


int get_connection() {
  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  assert(sock_fd >= 0);

  struct sockaddr_in sockaddr;
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1: localhost */
  sockaddr.sin_port = htons(4014);

  int reuse_address = 1;
  int rc = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
                      (void *) &reuse_address, sizeof(reuse_address));
  assert(rc == 0);
  rc = bind(sock_fd, (struct sockaddr *) &sockaddr, sizeof(sockaddr));
  assert(rc == 0);

  rc = listen(sock_fd, 1);
  assert(rc == 0);

  int fd = accept(sock_fd, NULL, 0);
  assert(fd >= 0);
  return fd;
}

int hex_to_int(char ch) {
  if ('0' <= ch && ch <= '9') {
    return ch - '0';
  } else if ('a' <= ch && ch <= 'f') {
    return ch - 'a' + 10;
  } else if ('A' <= ch && ch <= 'F') {
    return ch - 'A' + 10;
  } else {
    return 0;
  }
}

char int_to_hex(unsigned val) {
  assert(val < 16);
  if (val < 10) {
    return val + '0';
  } else {
    return val - 10 + 'a';
  }
}

void write_hex_byte(char *dest, uint8_t byte) {
  dest[0] = int_to_hex(byte >> 4);
  dest[1] = int_to_hex(byte & 0xf);
}

void write_hex_bytes(char *dest, uint8_t *data, size_t size) {
  size_t index;
  for (index = 0; index < size; index++) {
    write_hex_byte(dest, data[index]);
    dest += 2;
  }
}

int log_getc(FILE *fp) {
  int ch = getc(fp);
  if (ch == EOF) {
    fprintf(stderr, "Got EOF: exiting\n");
    exit(0);
  }
  return ch;
}

/* Read a message of the format "$<data>#<checksum>". */
void get_packet(FILE *fp, char *buffer, int buffer_size) {
  while (1) {
    /* Wait for the start character, '$', ignoring others. */
    while (1) {
      int ch = log_getc(fp);
      if (ch == '$')
        break;
      fprintf(stderr, "Unexpected char: '%c' (%i)\n", ch, ch);
    }

    int count = 0;
    uint8_t checksum = 0;
    while (1) {
      assert(count < buffer_size);
      char ch = log_getc(fp);
      if (ch == '#')
        break;
      checksum += ch;
      buffer[count++] = ch;
    }
    buffer[count] = 0;
    uint8_t received_checksum = hex_to_int(log_getc(fp)) << 4;
    received_checksum += hex_to_int(log_getc(fp));
    if (received_checksum != checksum) {
      fprintf(stderr, "got bad checksum: 0x%02x != 0x%02x\n",
              received_checksum, checksum);
      putc('-', fp);
    } else {
      putc('+', fp);
    }
    fflush(fp);
    if (received_checksum == checksum) {
      fprintf(stderr, "received: '%s'\n", buffer);
      return;
    }
  }
}

void put_packet(FILE *fp, char *packet) {
  putc('$', fp);
  uint8_t checksum = 0;
  char *ptr;
  for (ptr = packet; *ptr != 0; ptr++) {
    assert(*ptr != '$');
    assert(*ptr != '#');
    putc(*ptr, fp);
    checksum += *ptr;
  }
  putc('#', fp);
  putc(int_to_hex(checksum >> 4), fp);
  putc(int_to_hex(checksum & 0xf), fp);
  fprintf(stderr, "sent: '%s'\n", packet);
  /* Look for acknowledgement character. */
  int ch = log_getc(fp);
  if (ch != '+') {
    fprintf(stderr, "Unexpected ack char: '%c' (%i)\n", ch, ch);
  }
}

struct state {
  FILE *fp;
  int first_break;
} g_state;

struct gdb_regs {
#if defined(__i386__)
  uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
  uint32_t eip, eflags;
  uint32_t cs, ss, ds, es, fs, gs;
#elif defined(__x86_64__)
  uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
  uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
  uint64_t rip;
  uint32_t eflags;
  uint32_t cs, ss, ds, es, fs, gs;
#else
# error Unknown architecture
#endif
};

void copy_regs_to_gdb(struct gdb_regs *regs, const mcontext_t *mcontext) {
  memset(regs, 0, sizeof(*regs));
#if defined(__i386__)
  regs->eax = mcontext->gregs[REG_EAX];
  regs->ebx = mcontext->gregs[REG_EBX];
  regs->ecx = mcontext->gregs[REG_ECX];
  regs->edx = mcontext->gregs[REG_EDX];
  regs->esi = mcontext->gregs[REG_ESI];
  regs->edi = mcontext->gregs[REG_EDI];
  regs->esp = mcontext->gregs[REG_ESP];
  regs->ebp = mcontext->gregs[REG_EBP];
  regs->eflags = mcontext->gregs[REG_EFL];
  regs->eip = mcontext->gregs[REG_EIP];
#elif defined(__x86_64__)
  regs->rax = mcontext->gregs[REG_RAX];
  regs->rbx = mcontext->gregs[REG_RBX];
  regs->rcx = mcontext->gregs[REG_RCX];
  regs->rdx = mcontext->gregs[REG_RDX];
  regs->rsi = mcontext->gregs[REG_RSI];
  regs->rdi = mcontext->gregs[REG_RDI];
  regs->rbp = mcontext->gregs[REG_RBP];
  regs->rsp = mcontext->gregs[REG_RSP];
  regs->r8 = mcontext->gregs[REG_R8];
  regs->r9 = mcontext->gregs[REG_R9];
  regs->r10 = mcontext->gregs[REG_R10];
  regs->r11 = mcontext->gregs[REG_R11];
  regs->r12 = mcontext->gregs[REG_R12];
  regs->r13 = mcontext->gregs[REG_R13];
  regs->r14 = mcontext->gregs[REG_R14];
  regs->r15 = mcontext->gregs[REG_R15];
  regs->eflags = mcontext->gregs[REG_EFL];
  regs->rip = mcontext->gregs[REG_RIP];
#else
# error Unknown architecture
#endif
}

void signal_handler(int signum, siginfo_t *info, void *context) {
  ucontext_t *ucontext = context;
  mcontext_t *mcontext = &ucontext->uc_mcontext;

  if (!g_state.first_break) {
    char msg[100];
    snprintf(msg, sizeof(msg), "S%02x", signum);
    put_packet(g_state.fp, msg);
  }
  g_state.first_break = 0;

  /* Unset the trap flag in case we were single-stepping before.
     TODO: This should not be unconditional. */
  mcontext->gregs[REG_EFL] &= ~X86_TRAP_FLAG;

  while (1) {
    char request[100];
    get_packet(g_state.fp, request, sizeof(request));

    switch (request[0]) {
    case '?': /* query stopped status */
      {
        char reply[10];
        snprintf(reply, sizeof(reply), "S%02x", signum);
        put_packet(g_state.fp, reply);
      }
      break;
    case 'g': /* read registers */
      {
        char reply[1000];
        struct gdb_regs regs;
        copy_regs_to_gdb(&regs, mcontext);
        write_hex_bytes(reply, (uint8_t *) &regs, sizeof(regs));
        reply[sizeof(regs) * 2] = 0;
        put_packet(g_state.fp, reply);
        break;
      }
    case 'm': /* read memory */
      {
        char *rest;
        uintptr_t mem_addr = strtoll(request + 1, &rest, 16);
        assert(*rest == ',');
        size_t mem_size = strtoll(rest + 1, &rest, 16);
        assert(*rest == 0);
        char reply[1000];
        write_hex_bytes(reply, (uint8_t *) mem_addr, mem_size);
        reply[mem_size * 2] = 0;
        put_packet(g_state.fp, reply);
        break;
      }
    case 'c': /* continue */
      return;
    case 's': /* single step */
      mcontext->gregs[REG_EFL] = X86_TRAP_FLAG;
      return;
    default:
      put_packet(g_state.fp, "");
      break;
    }
  }
}

void test_prog() {
  while (1) {
    fprintf(stderr, "breaking...\n");
    asm("int3");
  }
}

int main() {
  int sock_fd = get_connection();
  FILE *fp = fdopen(sock_fd, "w+");
  assert(fp != NULL);

  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = signal_handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  int rc = sigaction(SIGTRAP, &act, NULL);
  assert(rc == 0);

  g_state.fp = fp;
  g_state.first_break = 1;

  test_prog();

  return 0;
}
