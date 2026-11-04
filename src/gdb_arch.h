/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#pragma once

#include <stdint.h>
#include <unistd.h>

/**
 * Index values used by gdb to reference general-purposed registers
 **/
enum gdb_gpr {
  GDB_GPR_RAX = 0,
  GDB_GPR_RBX,
  GDB_GPR_RCX,
  GDB_GPR_RDX,
  GDB_GPR_RSI,
  GDB_GPR_RDI,
  GDB_GPR_RBP,
  GDB_GPR_RSP,
  GDB_GPR_R8,
  GDB_GPR_R9,
  GDB_GPR_R10,
  GDB_GPR_R11,
  GDB_GPR_R12,
  GDB_GPR_R13,
  GDB_GPR_R14,
  GDB_GPR_R15,
  GDB_GPR_RIP,
  GDB_GPR_EFLAGS,
  GDB_GPR_CS,
  GDB_GPR_SS,
  GDB_GPR_DS,
  GDB_GPR_ES,
  GDB_GPR_FS,
  GDB_GPR_GS
};

#define GDB_GPR_MAX (GDB_GPR_GS+1)


int gdb_traceme(void);

int gdb_attach(pid_t pid);
int gdb_detach(pid_t pid, int sig);

int gdb_step(pid_t pid, intptr_t addr, int sig);
int gdb_continue(pid_t pid, intptr_t addr, int sig);

int gdb_getregs(pid_t pid, uint64_t regmap[GDB_GPR_MAX]);
int gdb_setregs(pid_t pid, const uint64_t regmap[GDB_GPR_MAX]);

int gdb_getreg(pid_t pid, enum gdb_gpr reg, uint64_t* val);
int gdb_setreg(pid_t pid, enum gdb_gpr reg, uint64_t val);

int gdb_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len);
int gdb_copyout(pid_t pid, intptr_t addr, void* buf, size_t len);

pid_t gdb_spawn(char* argv[], int stdio, intptr_t* baseaddr);


#define GDB_LIB_MAX_SEGS 4

#define GDB_SEG_READ  1
#define GDB_SEG_WRITE 2
#define GDB_SEG_EXEC  4


/**
 * A loadable segment of a shared library.
 **/
typedef struct gdb_seg {
  intptr_t addr;
  size_t   size;
  int      prot; // GDB_SEG_* flags
} gdb_seg_t;


/**
 * A shared library loaded in the address space of the interior.
 **/
typedef struct gdb_lib {
  char      name[256];
  uint32_t  handle;
  intptr_t  addr; // load address of the first segment
  int       nsegs;
  gdb_seg_t segs[GDB_LIB_MAX_SEGS];
} gdb_lib_t;


/**
 * A symbol exported by a shared library. The name is the raw (NID) name
 * truncated to 15 characters, and the value is an absolute address in the
 * address space of the process.
 **/
typedef struct gdb_sym {
  char     name[16];
  uint64_t value;
} gdb_sym_t;


/**
 * Enumerate the shared libraries loaded by a stopped process. Returns the
 * number of entries written to *libs*, or -1 on error.
 **/
int gdb_getlibs(pid_t pid, gdb_lib_t* libs, size_t max);


/**
 * Read the symbol table of a shared library loaded by a process. On success,
 * the number of symbols is returned and *syms* points to a malloc'd array the
 * caller must free. Returns -1 on error.
 **/
int gdb_getlibsyms(pid_t pid, uint32_t handle, gdb_sym_t** syms);
