/* Copyright (C) 2026 0xZ3n0x

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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gdb_symelf.h"
#include "nidtab.h"


#define PT_LOAD       1
#define SHT_SYMTAB    2
#define SHT_STRTAB    3
#define SHT_NOBITS    8
#define SHF_WRITE     1
#define SHF_ALLOC     2
#define SHF_EXECINSTR 4
#define PF_X          1
#define PF_W          2
#define PF_R          4
#define STB_GLOBAL    1
#define STT_OBJECT    1
#define STT_FUNC      2

// Sections: null, one per segment, .symtab, .strtab, .shstrtab
#define MAX_SECTIONS (GDB_LIB_MAX_SEGS + 4)


typedef struct {
  uint8_t  e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} elf_ehdr_t;

typedef struct {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} elf_phdr_t;

typedef struct {
  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  uint64_t sh_addr;
  uint64_t sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;
} elf_shdr_t;

typedef struct {
  uint32_t st_name;
  uint8_t  st_info;
  uint8_t  st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
} elf_sym_t;


/**
 * A symbol prepared for the output table.
 **/
typedef struct {
  uint64_t    value; // relative to the library load address
  const char* name;
  size_t      namelen;
  int         known; // name was resolved from a NID
} entry_t;


static int
gdb_nid_cmp(const void* key, const void* elem) {
  return strcmp((const char*)key, ((const gdb_nid_t*)elem)->nid);
}


const char*
gdb_nid_lookup(const char* nid) {
  const gdb_nid_t* e = bsearch(nid, gdb_nidtab, gdb_nidtab_len,
			       sizeof(gdb_nid_t), gdb_nid_cmp);
  return e ? e->name : 0;
}


static int
entry_cmp(const void* a, const void* b) {
  const entry_t* x = a;
  const entry_t* y = b;

  if(x->value != y->value) {
    return x->value < y->value ? -1 : 1;
  }

  // Resolved names first, so they win over raw NIDs at the same address.
  return y->known - x->known;
}


int
gdb_symelf_build(const gdb_lib_t* lib, const gdb_sym_t* syms,
		 size_t nsyms, char** buf, size_t* len) {
  const char* secnames[GDB_LIB_MAX_SEGS] = {0};
  char segname[GDB_LIB_MAX_SEGS][8];
  elf_shdr_t shdrs[MAX_SECTIONS];
  char shstr[128];
  size_t shstr_len = 1;
  size_t nsecs = 1;
  size_t nents = 0;
  size_t strtab_len = 1;
  size_t nout = 0;
  int text_seen = 0;
  entry_t* ents;
  char nid[12];

  memset(shdrs, 0, sizeof(shdrs));
  shstr[0] = 0;

  // Collect symbols, translating NIDs and keeping one name per address.
  if(!(ents=calloc(nsyms ? nsyms : 1, sizeof(entry_t)))) {
    return -1;
  }

  for(size_t i=0; i<nsyms; i++) {
    const char* name;

    if(syms[i].value < (uint64_t)lib->addr) {
      continue;
    }

    // Raw names have the form '<NID>#<lib>#<module>'.
    memcpy(nid, syms[i].name, 11);
    nid[11] = 0;
    if(strchr(nid, '#')) {
      *strchr(nid, '#') = 0;
    }

    ents[nents].value = syms[i].value - lib->addr;
    if((name=gdb_nid_lookup(nid))) {
      ents[nents].name = name;
      ents[nents].namelen = strlen(name);
      ents[nents].known = 1;
    } else {
      // Point into the source array; the NID is the first 11 characters.
      ents[nents].name = syms[i].name;
      ents[nents].namelen = strlen(nid);
      ents[nents].known = 0;
    }
    nents++;
  }

  qsort(ents, nents, sizeof(entry_t), entry_cmp);
  for(size_t i=0; i<nents; i++) {
    if(nout && ents[nout-1].value == ents[i].value) {
      continue;
    }
    ents[nout++] = ents[i];
  }

  // Section names.
  for(int i=0; i<lib->nsegs; i++) {
    if((lib->segs[i].prot & GDB_SEG_EXEC) && !text_seen) {
      secnames[i] = ".text";
      text_seen = 1;
    } else {
      snprintf(segname[i], sizeof(segname[i]), ".seg%d", i);
      secnames[i] = segname[i];
    }
  }

  // One NOBITS section per segment.
  for(int i=0; i<lib->nsegs; i++) {
    const gdb_seg_t* seg = &lib->segs[i];
    elf_shdr_t* sh = &shdrs[nsecs++];

    sh->sh_name = shstr_len;
    shstr_len += 1 + snprintf(shstr + shstr_len, sizeof(shstr) - shstr_len,
			      "%s", secnames[i]);
    sh->sh_type = SHT_NOBITS;
    sh->sh_flags = SHF_ALLOC;
    if(seg->prot & GDB_SEG_EXEC) {
      sh->sh_flags |= SHF_EXECINSTR;
    }
    if(seg->prot & GDB_SEG_WRITE) {
      sh->sh_flags |= SHF_WRITE;
    }
    sh->sh_addr = seg->addr - lib->addr;
    sh->sh_size = seg->size;
    sh->sh_addralign = 0x4000;
  }

  for(size_t i=0; i<nout; i++) {
    strtab_len += ents[i].namelen + 1;
  }

  // File layout: ehdr | phdrs | symtab | strtab | shstrtab | shdrs
  size_t nsegs = lib->nsegs;
  size_t phoff = sizeof(elf_ehdr_t);
  size_t symoff = phoff + nsegs * sizeof(elf_phdr_t);
  size_t symsz = (nout + 1) * sizeof(elf_sym_t);
  size_t stroff = symoff + symsz;
  size_t shstroff;
  size_t shoff;
  size_t total;
  char* img;

  // The remaining section names.
  size_t symtab_name = shstr_len;
  shstr_len += 1 + snprintf(shstr + shstr_len, sizeof(shstr) - shstr_len,
			    ".symtab");
  size_t strtab_name = shstr_len;
  shstr_len += 1 + snprintf(shstr + shstr_len, sizeof(shstr) - shstr_len,
			    ".strtab");
  size_t shstrtab_name = shstr_len;
  shstr_len += 1 + snprintf(shstr + shstr_len, sizeof(shstr) - shstr_len,
			    ".shstrtab");

  shstroff = stroff + strtab_len;
  shoff = (shstroff + shstr_len + 7) & ~(size_t)7;

  size_t symtab_idx = nsecs;
  shdrs[nsecs].sh_name = symtab_name;
  shdrs[nsecs].sh_type = SHT_SYMTAB;
  shdrs[nsecs].sh_offset = symoff;
  shdrs[nsecs].sh_size = symsz;
  shdrs[nsecs].sh_link = symtab_idx + 1;
  shdrs[nsecs].sh_info = 1;
  shdrs[nsecs].sh_addralign = 8;
  shdrs[nsecs].sh_entsize = sizeof(elf_sym_t);
  nsecs++;

  shdrs[nsecs].sh_name = strtab_name;
  shdrs[nsecs].sh_type = SHT_STRTAB;
  shdrs[nsecs].sh_offset = stroff;
  shdrs[nsecs].sh_size = strtab_len;
  shdrs[nsecs].sh_addralign = 1;
  nsecs++;

  shdrs[nsecs].sh_name = shstrtab_name;
  shdrs[nsecs].sh_type = SHT_STRTAB;
  shdrs[nsecs].sh_offset = shstroff;
  shdrs[nsecs].sh_size = shstr_len;
  shdrs[nsecs].sh_addralign = 1;
  nsecs++;

  total = shoff + nsecs * sizeof(elf_shdr_t);
  if(!(img=calloc(1, total))) {
    free(ents);
    return -1;
  }

  // ELF header.
  elf_ehdr_t* eh = (elf_ehdr_t*)img;
  memcpy(eh->e_ident, "\x7f" "ELF", 4);
  eh->e_ident[4] = 2; // ELFCLASS64
  eh->e_ident[5] = 1; // ELFDATA2LSB
  eh->e_ident[6] = 1; // EV_CURRENT
  eh->e_type = 3;     // ET_DYN
  eh->e_machine = 62; // EM_X86_64
  eh->e_version = 1;
  eh->e_phoff = phoff;
  eh->e_shoff = shoff;
  eh->e_ehsize = sizeof(elf_ehdr_t);
  eh->e_phentsize = sizeof(elf_phdr_t);
  eh->e_phnum = nsegs;
  eh->e_shentsize = sizeof(elf_shdr_t);
  eh->e_shnum = nsecs;
  eh->e_shstrndx = nsecs - 1;

  // Program headers mirror the segments, so gdb can relocate the file.
  elf_phdr_t* ph = (elf_phdr_t*)(img + phoff);
  for(size_t i=0; i<nsegs; i++) {
    const gdb_seg_t* seg = &lib->segs[i];
    ph[i].p_type = PT_LOAD;
    ph[i].p_flags = 0;
    if(seg->prot & GDB_SEG_READ) {
      ph[i].p_flags |= PF_R;
    }
    if(seg->prot & GDB_SEG_WRITE) {
      ph[i].p_flags |= PF_W;
    }
    if(seg->prot & GDB_SEG_EXEC) {
      ph[i].p_flags |= PF_X;
    }
    ph[i].p_vaddr = seg->addr - lib->addr;
    ph[i].p_paddr = ph[i].p_vaddr;
    ph[i].p_memsz = seg->size;
    ph[i].p_align = 0x4000;
  }

  // Symbol and string tables (entry 0 of both stays zeroed).
  elf_sym_t* st = (elf_sym_t*)(img + symoff);
  char* str = img + stroff;
  size_t stroff_cur = 1;
  size_t nsym_out = 1;

  for(size_t i=0; i<nout; i++) {
    size_t shndx = 0;
    int func = 0;

    for(size_t s=0; s<nsegs; s++) {
      uint64_t lo = lib->segs[s].addr - lib->addr;
      if(ents[i].value >= lo && ents[i].value < lo + lib->segs[s].size) {
	shndx = s + 1;
	func = lib->segs[s].prot & GDB_SEG_EXEC;
	break;
      }
    }
    if(!shndx) {
      continue;
    }

    st[nsym_out].st_name = stroff_cur;
    st[nsym_out].st_info = (STB_GLOBAL << 4) | (func ? STT_FUNC : STT_OBJECT);
    st[nsym_out].st_shndx = shndx;
    st[nsym_out].st_value = ents[i].value;
    nsym_out++;

    memcpy(str + stroff_cur, ents[i].name, ents[i].namelen);
    stroff_cur += ents[i].namelen + 1;
  }

  // Symbols outside of any segment were dropped; shrink the table to fit.
  shdrs[symtab_idx].sh_size = nsym_out * sizeof(elf_sym_t);

  memcpy(img + shstroff, shstr, shstr_len);
  memcpy(img + shoff, shdrs, nsecs * sizeof(elf_shdr_t));

  free(ents);
  *buf = img;
  *len = total;

  return 0;
}
