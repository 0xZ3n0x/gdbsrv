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

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ps5/kernel.h>

#include "gdb_arch.h"
#include "elfldr.h"
#include "pt.h"


static int
sys_ptrace(int request, pid_t pid, caddr_t addr, int data) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  pid_t mypid = getpid();
  uint8_t caps[16];
  uint64_t authid;
  int saved_errno;
  int ret;

  if(!(authid=kernel_get_ucred_authid(mypid))) {
    return -1;
  }
  if(kernel_get_ucred_caps(mypid, caps)) {
    return -1;
  }

  if(kernel_set_ucred_authid(mypid, 0x4800000000010003l)) {
    return -1;
  }
  if(kernel_set_ucred_caps(mypid, privcaps)) {
    // Restore the credentials partially set above before bailing out.
    kernel_set_ucred_authid(mypid, authid);
    return -1;
  }

  ret = (int)__syscall(SYS_ptrace, request, pid, addr, data);

  // Preserve the ptrace() errno; the kernel_* calls above will clobber it.
  saved_errno = errno;

  // Always attempt both restores, but report a failure: silently keeping
  // the elevated credentials would be worse than failing the request.
  if(kernel_set_ucred_authid(mypid, authid) |
     kernel_set_ucred_caps(mypid, caps)) {
    fprintf(stderr, "sys_ptrace: unable to restore credentials\n");
    errno = EPERM;
    return -1;
  }

  errno = saved_errno;

  return ret;
}


int
gdb_traceme(void) {
  return sys_ptrace(PT_TRACE_ME, 0, 0, 0);
}


int
gdb_attach(pid_t pid) {
  if(sys_ptrace(PT_ATTACH, pid, 0, 0)) {
    return -1;
  }

  return 0;
}


int
gdb_detach(pid_t pid, int sig) {
  if(sys_ptrace(PT_DETACH, pid, 0, sig)) {
    return -1;
  }

  return 0;
}


int
gdb_step(int pid, intptr_t addr, int sig) {
  if(!addr) {
    addr = 1;
  }

  if(sys_ptrace(PT_STEP, pid, (caddr_t)addr, sig)) {
    return -1;
  }

  return 0;
}


int
gdb_continue(pid_t pid, intptr_t addr, int sig) {
  if(!addr) {
    addr = 1;
  }

  if(sys_ptrace(PT_CONTINUE, pid, (caddr_t)addr, sig)) {
    return -1;
  }

  return 0;
}


int
gdb_getregs(pid_t pid, uint64_t gprmap[GDB_GPR_MAX]) {
  struct reg r;

  if(sys_ptrace(PT_GETREGS, pid, (caddr_t)&r, 0)) {
    return -1;
  }

  gprmap[GDB_GPR_RAX] = r.r_rax;
  gprmap[GDB_GPR_RBX] = r.r_rbx;
  gprmap[GDB_GPR_RCX] = r.r_rcx;
  gprmap[GDB_GPR_RDX] = r.r_rdx;
  gprmap[GDB_GPR_RSI] = r.r_rsi;
  gprmap[GDB_GPR_RDI] = r.r_rdi;
  gprmap[GDB_GPR_RBP] = r.r_rbp;
  gprmap[GDB_GPR_RSP] = r.r_rsp;
  gprmap[GDB_GPR_R8] = r.r_r8;
  gprmap[GDB_GPR_R9] = r.r_r9;
  gprmap[GDB_GPR_R10] = r.r_r10;
  gprmap[GDB_GPR_R11] = r.r_r11;
  gprmap[GDB_GPR_R12] = r.r_r12;
  gprmap[GDB_GPR_R13] = r.r_r13;
  gprmap[GDB_GPR_R14] = r.r_r14;
  gprmap[GDB_GPR_R15] = r.r_r15;
  gprmap[GDB_GPR_RIP] = r.r_rip;
  gprmap[GDB_GPR_EFLAGS] = r.r_rflags;
  gprmap[GDB_GPR_CS] = r.r_cs;
  gprmap[GDB_GPR_SS] = r.r_ss;
  gprmap[GDB_GPR_DS] = r.r_ds;
  gprmap[GDB_GPR_ES] = r.r_es;
  gprmap[GDB_GPR_FS] = r.r_fs;
  gprmap[GDB_GPR_GS] = r.r_gs;

  return 0;
}

int
gdb_setregs(pid_t pid, const uint64_t gprmap[GDB_GPR_MAX]) {
  struct reg r;

  if(sys_ptrace(PT_GETREGS, pid, (caddr_t)&r, 0)) {
    return -1;
  }

  r.r_rax = gprmap[GDB_GPR_RAX];
  r.r_rbx = gprmap[GDB_GPR_RBX];
  r.r_rcx = gprmap[GDB_GPR_RCX];
  r.r_rdx = gprmap[GDB_GPR_RDX];
  r.r_rsi = gprmap[GDB_GPR_RSI];
  r.r_rdi = gprmap[GDB_GPR_RDI];
  r.r_rbp = gprmap[GDB_GPR_RBP];
  r.r_rsp = gprmap[GDB_GPR_RSP];
  r.r_r8 = gprmap[GDB_GPR_R8];
  r.r_r9 = gprmap[GDB_GPR_R9];
  r.r_r10 = gprmap[GDB_GPR_R10];
  r.r_r11 = gprmap[GDB_GPR_R11];
  r.r_r12 = gprmap[GDB_GPR_R12];
  r.r_r13 = gprmap[GDB_GPR_R13];
  r.r_r14 = gprmap[GDB_GPR_R14];
  r.r_r15 = gprmap[GDB_GPR_R15];
  r.r_rip = gprmap[GDB_GPR_RIP];
  r.r_rflags = gprmap[GDB_GPR_EFLAGS];
  r.r_cs = gprmap[GDB_GPR_CS];
  r.r_ss = gprmap[GDB_GPR_SS];
  r.r_ds = gprmap[GDB_GPR_DS];
  r.r_es = gprmap[GDB_GPR_ES];
  r.r_fs = gprmap[GDB_GPR_FS];
  r.r_gs = gprmap[GDB_GPR_GS];

  if(sys_ptrace(PT_SETREGS, pid, (caddr_t)&r, 0)) {
    return -1;
  }

  return 0;
}


int
gdb_setreg(pid_t pid, enum gdb_gpr reg, uint64_t val) {
  uint64_t gprmap[GDB_GPR_MAX];

  if(gdb_getregs(pid, gprmap)) {
    return -1;
  }

  gprmap[reg] = val;

  return gdb_setregs(pid, gprmap);
}


int
gdb_getreg(pid_t pid, enum gdb_gpr reg, uint64_t* val) {
  uint64_t gprmap[GDB_GPR_MAX];

  if(gdb_getregs(pid, gprmap)) {
    return -1;
  }

  *val = gprmap[reg];

  return 0;
}


int
gdb_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len) {
  return pt_copyin(pid, buf, addr, len);
}


int
gdb_copyout(pid_t pid, intptr_t addr, void* buf, size_t len) {
  return pt_copyout(pid, addr, buf, len);
}


int
gdb_spawn(char* argv[], int stdio, intptr_t* baseaddr) {
  return elfldr_spawn(argv, stdio, baseaddr);
}


#define SYS_dynlib_get_list 592
#define SYS_dynlib_get_info 593
#define DYNLIB_MAX_HANDLES  256


typedef struct dynlib_segment {
  uint64_t addr;
  uint32_t size;
  int32_t  prot;
} dynlib_segment_t;


typedef struct dynlib_info {
  uint64_t         size; // must be set to sizeof(dynlib_info_t) by the caller
  char             name[256];
  dynlib_segment_t segs[4];
  uint32_t         nsegs;
  uint8_t          fingerprint[20];
} dynlib_info_t;

_Static_assert(sizeof(dynlib_info_t) == 0x160, "dynlib_info_t size mismatch");


int
gdb_getlibs(pid_t pid, gdb_lib_t* libs, size_t max) {
  // Layout of the scratch memory mapped in the interior.
  const size_t   memsize = 0x4000;
  const intptr_t handles_off = 0;
  const intptr_t count_off = DYNLIB_MAX_HANDLES * sizeof(uint32_t);
  const intptr_t info_off = count_off + 0x100;

  uint32_t handles[DYNLIB_MAX_HANDLES];
  dynlib_info_t info;
  uint64_t count = 0;
  intptr_t mem;
  size_t n = 0;

  // The dynlib syscalls only operate on the calling process, so they are
  // executed inside the (stopped) interior, using scratch memory there.
  mem = pt_mmap(pid, 0, memsize, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if(mem == -1 || (uintptr_t)mem < 0x10000) {
    errno = ENOMEM;
    return -1;
  }

  if(pt_syscall(pid, SYS_dynlib_get_list, mem + handles_off,
		(uint64_t)DYNLIB_MAX_HANDLES, mem + count_off) ||
     pt_copyout(pid, mem + count_off, &count, sizeof(count))) {
    pt_munmap(pid, mem, memsize);
    errno = EIO;
    return -1;
  }

  if(count > DYNLIB_MAX_HANDLES) {
    count = DYNLIB_MAX_HANDLES;
  }
  if(pt_copyout(pid, mem + handles_off, handles, count * sizeof(uint32_t))) {
    pt_munmap(pid, mem, memsize);
    errno = EIO;
    return -1;
  }

  for(uint64_t i=0; i<count && n<max; i++) {
    // Handle 0 is the eboot of the host process, not a shared library.
    if(!handles[i]) {
      continue;
    }

    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    if(pt_copyin(pid, &info, mem + info_off, sizeof(info))) {
      continue;
    }
    if(pt_syscall(pid, SYS_dynlib_get_info, (uint64_t)handles[i],
		  mem + info_off)) {
      continue;
    }
    if(pt_copyout(pid, mem + info_off, &info, sizeof(info))) {
      continue;
    }

    info.name[sizeof(info.name)-1] = 0;
    if(!info.name[0] || !info.nsegs || !info.segs[0].addr) {
      continue;
    }

    snprintf(libs[n].name, sizeof(libs[n].name), "%s", info.name);
    libs[n].handle = handles[i];
    libs[n].addr = (intptr_t)info.segs[0].addr;
    libs[n].nsegs = 0;
    for(uint32_t s=0; s<info.nsegs && s<GDB_LIB_MAX_SEGS; s++) {
      gdb_seg_t* seg = &libs[n].segs[libs[n].nsegs];
      if(!info.segs[s].addr || !info.segs[s].size) {
	continue;
      }
      seg->addr = (intptr_t)info.segs[s].addr;
      seg->size = info.segs[s].size;
      seg->prot = 0;
      if(info.segs[s].prot & PROT_READ) {
	seg->prot |= GDB_SEG_READ;
      }
      if(info.segs[s].prot & PROT_WRITE) {
	seg->prot |= GDB_SEG_WRITE;
      }
      if(info.segs[s].prot & PROT_EXEC) {
	seg->prot |= GDB_SEG_EXEC;
      }
      libs[n].nsegs++;
    }
    n++;
  }

  pt_munmap(pid, mem, memsize);

  return (int)n;
}


// Exported by the SDK runtime (crt1.o), but not declared in <ps5/kernel.h>.
// Copies the kernel dynlib object of a library loaded by *pid* to *obj*.
int kernel_dynlib_obj(pid_t pid, uint32_t handle, void* obj);


// Layout of the kernel dynlib object, as used by the SDK's own
// kernel_dynlib_resolve().
#define DYNLIB_OBJ_SIZE        0x400 // larger than the object (<= 0x180)
#define DYNLIB_OBJ_IMAGEBASE   0x30
#define DYNLIB_OBJ_DYNSEC      0x148
#define DYNLIB_DYNSEC_SIZE     0x120
#define DYNLIB_DYNSEC_SYMTAB   0x28
#define DYNLIB_DYNSEC_SYMTABSZ 0x30
#define DYNLIB_DYNSEC_STRTAB   0x38
#define DYNLIB_DYNSEC_STRTABSZ 0x40
#define DYNLIB_TABLE_MAX       (16 * 1024 * 1024)


typedef struct elf64_sym {
  uint32_t st_name;
  uint8_t  st_info;
  uint8_t  st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
} elf64_sym_t;


int
gdb_getlibsyms(pid_t pid, uint32_t handle, gdb_sym_t** syms) {
  uint8_t obj[DYNLIB_OBJ_SIZE];
  uint8_t dynsec[DYNLIB_DYNSEC_SIZE];
  uint64_t symtab, symtabsz, strtab, strtabsz, base, kdynsec;
  elf64_sym_t* symbuf;
  char* strbuf;
  size_t mapsz, nsyms, n = 0;
  gdb_sym_t* out;
  void* mem;

  *syms = 0;

  memset(obj, 0, sizeof(obj));
  if(kernel_dynlib_obj(pid, handle, obj)) {
    errno = ENOENT;
    return -1;
  }

  memcpy(&base, obj + DYNLIB_OBJ_IMAGEBASE, sizeof(base));
  memcpy(&kdynsec, obj + DYNLIB_OBJ_DYNSEC, sizeof(kdynsec));
  if(!kdynsec || kernel_copyout(kdynsec, dynsec, sizeof(dynsec)) < 0) {
    errno = EIO;
    return -1;
  }

  memcpy(&symtab, dynsec + DYNLIB_DYNSEC_SYMTAB, sizeof(symtab));
  memcpy(&symtabsz, dynsec + DYNLIB_DYNSEC_SYMTABSZ, sizeof(symtabsz));
  memcpy(&strtab, dynsec + DYNLIB_DYNSEC_STRTAB, sizeof(strtab));
  memcpy(&strtabsz, dynsec + DYNLIB_DYNSEC_STRTABSZ, sizeof(strtabsz));

  // Sanity check the tables before trusting their sizes.
  if(!symtab || !strtab || !symtabsz || !strtabsz ||
     symtabsz % sizeof(elf64_sym_t) || symtabsz > DYNLIB_TABLE_MAX ||
     strtabsz > DYNLIB_TABLE_MAX) {
    errno = EINVAL;
    return -1;
  }

  // Like the SDK, copy the tables into freshly mapped user memory.
  mapsz = (symtabsz + strtabsz + 1 + 0x3fff) & ~(size_t)0x3fff;
  if((mem=mmap(0, mapsz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
	       -1, 0)) == MAP_FAILED) {
    return -1;
  }
  symbuf = mem;
  strbuf = (char*)mem + symtabsz;

  if(kernel_copyout(symtab, symbuf, symtabsz) < 0 ||
     kernel_copyout(strtab, strbuf, strtabsz) < 0) {
    munmap(mem, mapsz);
    errno = EIO;
    return -1;
  }
  strbuf[strtabsz] = 0;

  nsyms = symtabsz / sizeof(elf64_sym_t);
  if(!(out=calloc(nsyms ? nsyms : 1, sizeof(gdb_sym_t)))) {
    munmap(mem, mapsz);
    return -1;
  }

  for(size_t i=0; i<nsyms; i++) {
    // Skip undefined (imported) symbols and malformed names.
    if(!symbuf[i].st_value || !symbuf[i].st_shndx ||
       symbuf[i].st_name >= strtabsz) {
      continue;
    }

    snprintf(out[n].name, sizeof(out[n].name), "%s",
	     strbuf + symbuf[i].st_name);
    out[n].value = base + symbuf[i].st_value;
    n++;
  }

  munmap(mem, mapsz);
  *syms = out;

  return (int)n;
}

