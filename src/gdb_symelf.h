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

#pragma once

#include <stddef.h>

#include "gdb_arch.h"


/**
 * Build an in-memory ELF that gdb can load symbols from: the segments of
 * *lib* (relative to its load address) as NOBITS sections, and a symbol
 * table where NIDs are translated to names when known.
 *
 * On success, *buf* points to a malloc'd image of *len* bytes and 0 is
 * returned; -1 is returned on error.
 **/
int gdb_symelf_build(const gdb_lib_t* lib, const gdb_sym_t* syms,
		     size_t nsyms, char** buf, size_t* len);
