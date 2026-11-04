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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <sys/wait.h>

#include "gdb_arch.h"
#include "gdb_pkt.h"
#include "gdb_resp.h"
#include "gdb_sig.h"


#define STR_START_WITH(str, prefix) (!memcmp(str, prefix, strlen(prefix)))


/**
 * Keep track of the session state.
 **/
typedef struct gdb_session {
  pid_t pid;
  int fd;
  int sig;
  int stdio;
  int attached;
  int code;
  intptr_t baseaddr;
  char runfile[PATH_MAX];
} gdb_session_t;


/**
 * Help the client identify the target architecture.
 **/
static char target_xml[] = "<?xml version=\"1.0\"?>\n" \
  "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
  "<target>\n"
  "<architecture>i386:x86-64</architecture>\n"
  "<osabi>none</osabi>\n"
  "</target>\n";


/**
 * Unescape binary data trasnmitted from gdb.
 **/
static int
gdb_bin_unescape(char *data, int len) {
  char *w = data;
  char *r = data;

  while(r - data < len) {
    char v = *r++;
    if(v != '}') {
      *w++ = v;
      continue;
    }
    if(r - data >= len) {
      // Dangling escape character at the end of the buffer; drop it.
      break;
    }
    *w++ = *r++ ^ 0x20;
  }

  return w - data;
}


/**
 * Convert a hexstring into its binary representation.
 **/
static int
gdb_hex2bin(const char* str, void* bin, size_t size) {
  int len = strlen(str);
  uint8_t* ptr = bin;
  int ch;

  if((size_t)len > size*2 || len%2) {
    return -1;
  }

  memset(bin, 0, size);
  for(int i=0; i<len; i+=2, ptr++) {
    if(sscanf(str+i, "%02x", &ch) != 1) {
      return -1;
    }
    *ptr = ch;
  }

  return 0;
}


/**
 * Parse the address and signal arguments of the [cCsS] packets.
 **/
static void
gdb_parse_stepcont(const char* data, intptr_t* addr, int* sig) {
  const char* semi;
  unsigned long a = 0;
  unsigned int s = 0;

  *addr = 0;
  *sig = 0;

  switch(data[0]) {
  case 'c':
  case 's':
    // 'c [addr]' / 's [addr]'
    sscanf(data + 1, "%lx", &a);
    *addr = (intptr_t)a;
    break;

  case 'C':
  case 'S':
    // 'C sig[;addr]' / 'S sig[;addr]'
    if(sscanf(data + 1, "%2x", &s) == 1) {
      *sig = (int)s;
    }
    if((semi = strchr(data + 1, ';'))) {
      sscanf(semi + 1, "%lx", &a);
      *addr = (intptr_t)a;
    }
    break;
  }
}


/**
 * Forward whatever the interior has left in its stdout pipe.
 **/
static void
gdb_drain_stdio(gdb_session_t* sess) {
  char buf[0x100];
  ssize_t len;

  if(sess->stdio <= 0) {
    return;
  }

  for(int i=0; i<64; i++) {
    if((len=read(sess->stdio, buf, sizeof(buf))) <= 0) {
      break;
    }
    if(gdb_pkt_notify(sess->fd, buf, len)) {
      break;
    }
  }
}


/**
 * Release the interior: detached processes are resumed, processes that
 * were spawned through vRun are killed and reaped.
 **/
static void
gdb_halt_inferior(gdb_session_t* sess) {
  if(sess->pid > 0) {
    if(sess->attached) {
      gdb_detach(sess->pid, SIGCONT);
    } else {
      gdb_detach(sess->pid, SIGKILL);
      waitpid(sess->pid, 0, 0);
    }
    sess->pid = -1;
  }

  if(sess->stdio > 0) {
    close(sess->stdio);
    sess->stdio = -1;
  }

  sess->attached = 0;
}


/**
 * Flush stdout of the interior to the connecting client,
 * and look for Ctrl-c sequence from the client.
 *
 * Returns 0 to keep waiting, a signal number to deliver to the interior,
 * or -1 if the client connection is gone.
 **/
static int
gdb_response_stdio(gdb_session_t* sess) {
  struct pollfd fds[2];
  char buf[0x100];
  ssize_t len;
  int cnt = 1;

  memset(fds, 0, sizeof(fds));

  fds[0].fd = sess->fd;
  fds[0].events = POLLIN;

  fds[1].fd = sess->stdio;
  fds[1].events = POLLIN;

  if(fds[1].fd > 0) {
    cnt++;
  }

  switch(poll(fds, cnt, 1)) {
  case -1:
    if(EINTR == errno) {
      return 0;
    }
    if(gdb_pkt_notify_perror(sess->fd, "poll")) {
      perror("gdb_pkt_notify_perror");
    }
    return SIGSTOP;

  case 0:
    return 0;

  default:
    if(fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
      if((len=read(sess->fd, buf, 1)) < 0) {
	if(EAGAIN == errno || EINTR == errno) {
	  return 0;
	}
	perror("read");
	return -1;
      }

      if(len == 0) {
	// The client has closed the connection.
	return -1;
      }

      if(buf[0] == 3) {
	return SIGSTOP;
      }
    }

    if(cnt > 1 && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
      if((len=read(sess->stdio, buf, sizeof(buf))) <= 0) {
	// EOF or error on the stdout pipe of the interior; stop polling it
	// so we do not spin on a hung-up descriptor.
	if(len < 0) {
	  perror("read");
	}
	close(sess->stdio);
	sess->stdio = -1;
	return 0;
      }

      if(gdb_pkt_notify(sess->fd, buf, len) < 0) {
	if(errno == EINTR) {
	  // Ctrl-c received while waiting for the ack.
	  return SIGSTOP;
	}

	perror("gdb_pkt_notify");
	return -1;
      }
    }
  }

  return 0;
}



/**
 * Wait for a signal, and copy a gdb packet response to *data*.
 **/
static int
gdb_waitpid(gdb_session_t* sess, char* data, size_t size) {
  int status = 0;
  int res;

  while(1) {
    if((res=waitpid(sess->pid, &status, WNOHANG | WUNTRACED)) < 0) {
      return -1;
    }

    if(!res) {
      if((res=gdb_response_stdio(sess)) < 0) {
	// Client is gone; let the caller tear the session down.
	errno = ECONNRESET;
	return -1;
      }
      if(res) {
	kill(sess->pid, res);
      }
      continue;
    }

    if(WIFEXITED(status)) {
      gdb_drain_stdio(sess);
      sess->code = WEXITSTATUS(status);
      sess->pid = -1;
      snprintf(data, size, "W%02x", sess->code);
      return 0;

    } else if(WIFSIGNALED(status)) {
      gdb_drain_stdio(sess);
      sess->sig = WTERMSIG(status);
      sess->pid = -1;
      snprintf(data, size, "X%02x", gdb_sig_fromposix(sess->sig));
      return 0;

    } else if(WIFSTOPPED(status)) {
      sess->sig = WSTOPSIG(status);
      snprintf(data, size, "S%02x", gdb_sig_fromposix(sess->sig));
      return 0;
    }
  }

  return 0;
}


/**
 * Input pattern: '!'
 *
 * Enable extended mode. In extended mode, the remote server is made persistent.
 * The 'R' packet is used to restart the program being debugged.
 *
 * Reply:
 *   'OK' - The remote target both supports and has enabled extended mode.
 **/
static int
gdb_response_extended_mode(gdb_session_t* sess, const char* data, size_t size) {
  return gdb_pkt_puts(sess->fd, "OK");
}


/**
 * Input pattern: '?'
 *
 * This is sent when connection is first established to query the reason the
 * target halted. The reply is the same as for step and continue. This packet
 * has a special interpretation when the target is in non-stop mode; see Remote
 * Non-Stop.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 **/
static int
gdb_response_getsig(gdb_session_t* sess, const char* data, size_t size) {
  if(sess->pid > 0) {
    return gdb_pkt_printf(sess->fd, "S%02X", gdb_sig_fromposix(sess->sig));
  }

  return gdb_pkt_printf(sess->fd, "W%02X", sess->code);
}


/**
 * Input pattern: 'c [addr]'
 *
 * Continue at addr, which is the address to resume. If addr is omitted, resume
 * at current address.
 *
 *  This packet is deprecated for multi-threading support. See vCont packet.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 *
 * -----------------------------------------------------------------------------
 *
 * Input pattern: 'C sig[;addr]'
 *
 * Continue with signal sig (hex signal number). If ‘;addr’ is omitted, resume
 * at same address.
 *
 * This packet is deprecated for multi-threading support. See vCont packet.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 **/
static int
gdb_response_continue(gdb_session_t* sess, const char* data, size_t size) {
  intptr_t addr = 0;
  char buf[32];
  int sig = 0;

  gdb_parse_stepcont(data, &addr, &sig);
  sig = gdb_sig_toposix(sig);

  // Never re-inject the signals that typically cause a stop; resume
  // without a signal instead.
  if(SIGSTOP == sig || SIGTRAP == sig) {
    sig = 0;
  }

  if(gdb_continue(sess->pid, addr, sig)) {
    return gdb_pkt_perror(sess->fd, "gdb_continue");
  }

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 * Input pattern: 'D[;pid]'
 *
 * The first form of the packet is used to detach GDB from the remote system.
 * It is sent to the remote target before GDB disconnects via the detach
 * command.
 *
 * The second form, including a process ID, is used when multiprocess protocol
 * extensions are enabled (see multiprocess extensions), to detach only a
 * specific process. The pid is specified as a big-endian hex string.
 *
 * Reply:
     ‘OK’ for success
 **/
static int
gdb_response_detach(gdb_session_t* sess, const char* data, size_t size) {
  unsigned int upid;
  pid_t pid = sess->pid;

  if(sscanf(data, "D;%x", &upid) == 1) {
    // Detaching a specific process; we only manage a single one.
    if((pid_t)upid != pid) {
      return gdb_pkt_puts(sess->fd, "");
    }
  } else if(strcmp(data, "D")) {
    return gdb_pkt_puts(sess->fd, "");
  }

  if(pid > 0 && gdb_detach(pid, SIGCONT)) {
    return gdb_pkt_perror(sess->fd, "gdb_detach");
  }

  sess->pid = -1;
  sess->attached = 0;

  return gdb_pkt_puts(sess->fd, "OK");
}


/**
 * Input pattern: 'g'
 *
 * Read general registers.
 *
 * Reply:
 *   XX...
 *
 * Each byte of register data is described by two hex digits. The bytes with
 * the register are transmitted in target byte order. The size of each register
 * and their position within the 'g' packet are determined by the target
 * description (see Target Descriptions); in the absence of a target
 * description, this is done using code internal to GDB; typically this is some
 * customary register layout for the architecture in question.
 *
 * When reading registers, the stub may also return a string of literal x's
 * in place of the register data digits, to indicate that the corresponding
 * register’s value is unavailable. For example, when reading registers from a
 * trace frame (see Using the Collected Data), this means that the register has
 * not been collected in the trace frame. When reading registers from a live
 * program, this indicates that the stub has no means to access the register
 * contents, even though the corresponding register is known to exist. Note
 * that if a register truly does not exist on the target, then it is better to
 * not include it in the target description in the first place.
 *
 * For example, for an architecture with 4 registers of 4 bytes each, the
 * following reply indicates to GDB that registers 0 and 2 are unavailable,
 * while registers 1 and 3 are available, and both have zero value:
 *
 *      -> g
 *      <- xxxxxxxx00000000xxxxxxxx00000000
 **/
static int
gdb_response_getregs(gdb_session_t* sess, const char* data, size_t size) {
  uint64_t gprmap[GDB_GPR_MAX];
  char buf[(GDB_GPR_MAX*16)+1];
  char* p = buf;

  if(gdb_getregs(sess->pid, gprmap)) {
    return gdb_pkt_perror(sess->fd, "gdb_getregs");
  }

  for(int i=GDB_GPR_RAX; i<=GDB_GPR_RIP; i++) {
    sprintf(p, "%016lx", __builtin_bswap64(gprmap[i]));
    p += 16;
  }

  for(int i=GDB_GPR_EFLAGS; i<=GDB_GPR_GS; i++) {
    sprintf(p, "%08x", __builtin_bswap32(gprmap[i]));
    p += 8;
  }
  *p = 0;

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 * Input pattern: 'G XX...'
 *
 * Write general registers. See read registers packet, for a description of
 * the XX... data.
 *
 * Reply:
 *   'OK' for success
 **/
static int
gdb_response_setregs(gdb_session_t* sess, const char* data, size_t size) {
  uint64_t gprmap[GDB_GPR_MAX];
  size_t required = ((GDB_GPR_RIP + 1) * 16) +
    ((GDB_GPR_GS - GDB_GPR_EFLAGS + 1) * 8);

  data++;
  if(strlen(data) < required) {
    return gdb_pkt_puts(sess->fd, "");
  }

  for(int i=GDB_GPR_RAX; i<=GDB_GPR_RIP; i++) {
    long val;
    if(sscanf(data, "%016lx", &val) != 1) {
      return gdb_pkt_puts(sess->fd, "");
    }
    data += 16;
    gprmap[i] = __builtin_bswap64(val);
  }

  for(int i=GDB_GPR_EFLAGS; i<=GDB_GPR_GS; i++) {
    int val;
    if(sscanf(data, "%08x", &val) != 1) {
      return gdb_pkt_puts(sess->fd, "");
    }
    data += 8;
    gprmap[i] = __builtin_bswap32(val);
  }

  if(gdb_setregs(sess->pid, gprmap)) {
    return gdb_pkt_perror(sess->fd, "gdb_setregs");
  }

  return gdb_pkt_puts(sess->fd, "OK");
}


/**
 * Input pattern: 'k'
 *
 * Kill request.
 *
 * The exact effect of this packet is not specified.
 *
 * For a bare-metal target, it may power cycle or reset the target system.
 * For that reason, the ‘k’ packet has no reply.
 *
 * For a single-process target, it may kill that process if possible.
 *
 * A multiple-process target may choose to kill just one process, or all that
 * are under GDB's control. For more precise control, use the vKill packet (see
 * vKill packet).
 *
 * If the target system immediately closes the connection in response to ‘k’,
 * GDB does not consider the lack of packet acknowledgment to be an error, and
 * assumes the kill was successful.
 *
 * If connected using target extended-remote, and the target does not close the
 * connection in response to a kill request, GDB probes the target state as if
 * a new connection was opened (see ? packet).
 **/
static int
gdb_response_kill(gdb_session_t* sess, const char* data, size_t size) {
  gdb_halt_inferior(sess);

  // The 'k' packet has no reply; gdb will close the connection or probe
  // the target state through the '?' packet.
  return 0;
}


/**
 * Input pattern: 'm addr,length'
 *
 * Read length addressable memory units starting at address addr (see
 * addressable memory unit). Note that addr may not be aligned to any particular
 * boundary.
 *
 * The stub need not use any particular size or alignment when gathering data
 * from memory for the response; even if addr is word-aligned and length is a
 * multiple of the word size, the stub is free to use byte accesses, or not.
 * For this reason, this packet may not be suitable for accessing memory-mapped
 * I/O devices.
 *
 * Reply:
 *   XX...
 *
 * Memory contents; each byte is transmitted as a two-digit hexadecimal number.
 * The reply may contain fewer addressable memory units than requested if the
 * server was able to read only part of the region of memory.
 *
 * Unlike most packets, this packet does not support ‘E.errtext’-style textual
 *error replies (see textual error reply).
 **/
static int
gdb_response_getmem(gdb_session_t* sess, const char* data, size_t size) {
  char dbuf[GDB_PKT_MAX_SIZE / 2];
  char sbuf[GDB_PKT_MAX_SIZE];
  char* p = sbuf;
  unsigned long addr;
  unsigned long len;

  if(sscanf(data, "m%lx,%lx", &addr, &len) != 2) {
    return gdb_pkt_puts(sess->fd, "");
  }

  // gdb tolerates a short reply; clamp instead of rejecting.
  if(len > (sizeof(dbuf) - 1)) {
    len = sizeof(dbuf) - 1;
  }

  if(gdb_copyout(sess->pid, (intptr_t)addr, dbuf, len)) {
    return gdb_pkt_printf(sess->fd, "E%02X", ((errno ? errno : EIO) & 0xff));
  }

  for(size_t i=0; i<len; i++) {
    sprintf(p, "%02x", (uint8_t)dbuf[i]);
    p += 2;
  }
  *p = 0;

  return gdb_pkt_puts(sess->fd, sbuf);
}


/**
 * Input pattern: 'M addr,length:XX...'
 *
 * Write length addressable memory units starting at address addr (see
 * addressable memory unit). The data is given by XX...; each byte is
 * transmitted as a two-digit hexadecimal number.
 *
 * Reply:
     'OK' - All the data was written successfully. (If only part of the
           data was written, this command returns an error.)
 **/
static int
gdb_response_setmem(gdb_session_t* sess, const char* data, size_t size) {
  unsigned long addr;
  unsigned long len;
  const char* p;
  char* buf;
  int r;

  if(sscanf(data, "M%lx,%lx:", &addr, &len) != 2) {
    return gdb_pkt_printf(sess->fd, "E%02X", (EINVAL & 0xff));
  }

  // The hex payload requires at least 2 characters per byte, and the
  // whole packet is bounded by GDB_PKT_MAX_SIZE.
  if(len == 0 || len > ((GDB_PKT_MAX_SIZE / 2) - 1)) {
    return gdb_pkt_printf(sess->fd, "E%02X", (EINVAL & 0xff));
  }

  if(!(p=strchr(data, ':'))) {
    return gdb_pkt_printf(sess->fd, "E%02X", (EINVAL & 0xff));
  }

  if(!(buf=malloc(len))) {
    return gdb_pkt_printf(sess->fd, "E%02X", (ENOMEM & 0xff));
  }

  // The payload must carry exactly two hex digits per byte; a short
  // payload would otherwise be zero-padded and written to the interior.
  if(strlen(p + 1) != len * 2 || gdb_hex2bin(p + 1, buf, len)) {
    free(buf);
    return gdb_pkt_printf(sess->fd, "E%02X", (EINVAL & 0xff));
  }

  if(gdb_copyin(sess->pid, buf, (intptr_t)addr, len)) {
    r = gdb_pkt_printf(sess->fd, "E%02X", ((errno ? errno : EIO) & 0xff));
  } else {
    r = gdb_pkt_puts(sess->fd, "OK");
  }

  free(buf);

  return r;
}


/**
 * Input pattern: 'p n'
 *
 * Read the value of register n; n is in hex. See read registers packet, for a
 * description of how the returned register value is encoded.
 *
 * Reply:
 *   XX... the register’s value
 **/
static int
gdb_response_getreg(gdb_session_t* sess, const char* data, size_t size) {
  unsigned int reg;
  uint64_t val;

  if(sscanf(data, "p%x", &reg) != 1 || reg >= GDB_GPR_MAX) {
    return gdb_pkt_puts(sess->fd, "");
  }

  if(gdb_getreg(sess->pid, (enum gdb_gpr)reg, &val)) {
    return gdb_pkt_perror(sess->fd, "gdb_getreg");
  }

  if(reg <= GDB_GPR_RIP) {
    return gdb_pkt_printf(sess->fd, "%016lx", __builtin_bswap64(val));
  } else {
    return gdb_pkt_printf(sess->fd, "%08x", __builtin_bswap32(val));
  }
}


/**
 * Input pattern: 'P n...=r...'
 *
 * Write register n... with value r..., where the register number n is in
 * hexadecimal and r... contains two hex digits for each byte in the
 * register (target byte order).
 *
 * Reply:
     'OK' for success
 **/
static int
gdb_response_setreg(gdb_session_t* sess, const char* data, size_t size) {
  unsigned int reg;
  unsigned long val;

  if(sscanf(data, "P%x=%lx", &reg, &val) != 2) {
    return gdb_pkt_puts(sess->fd, "");
  }

  if(reg >= GDB_GPR_MAX) {
    // gdb may poke registers that are not part of our target description
    // (e.g. orig_rax); accept such writes silently.
    return gdb_pkt_puts(sess->fd, "OK");
  }

  if(reg <= GDB_GPR_RIP) {
    val = __builtin_bswap64(val);
  } else {
    val = __builtin_bswap32(val);
  }

  if(gdb_setreg(sess->pid, (enum gdb_gpr)reg, val)) {
    return gdb_pkt_perror(sess->fd, "gdb_setreg");
  }

  return gdb_pkt_puts(sess->fd, "OK");
}



/**
 * Input pattern: 'qAttached:pid'
 *
 * Return an indication of whether the remote server attached to an existing
 * process or created a new process. When the multiprocess protocol extensions
 * are supported (see multiprocess extensions), pid is an integer in hexadecimal
 * format identifying the target process. Otherwise, GDB will omit the pid field
 * and the query packet will be simplified as 'qAttached'.
 *
 * This query is used, for example, to know whether the remote process should be
 * detached or killed when a gdb session is ended with the quit command.
 *
 * Reply:
     '1' - The remote server attached to an existing process.
     '0' - The remote server created a new process.
 **/
static int
gdb_response_attached(gdb_session_t* sess, const char* data, size_t size) {
  return gdb_pkt_printf(sess->fd, "%d", sess->attached && (sess->pid > 0));
}


/**
 * Input pattern: 'qOffsets'
 *
 * Get section offsets that the target used when relocating the downloaded image.
 *
 * Reply:
 *   'Text=xxx;Data=yyy;Bss=zzz'
 *
 * Relocate the Text section by xxx from its original address. Relocate the Data
 * section by yyy from its original address. If the object file format provides
 * segment information (e.g. ELF ‘PT_LOAD’ program headers), GDB will relocate
 * entire segments by the supplied offsets.
 *
 * Note: while a Bss offset may be included in the response, GDB ignores this
 * and instead applies the Data offset to the Bss section.
 *
 *   'TextSeg=xxx;DataSeg=yyy'
 *
 * Relocate the first segment of the object file, which conventionally contains
 * program code, to a starting address of xxx. If ‘DataSeg’ is specified,
 * relocate the second segment, which conventionally contains modifiable data,
 * to a starting address of yyy. GDB will report an error if the object file
 * does not contain segment information, or does not contain at least as many
 * segments as mentioned in the reply. Extra segments are kept at fixed offsets
 * relative to the last relocated segment.
 **/
static int
gdb_response_offsets(gdb_session_t* sess, const char* data, size_t size) {
  return gdb_pkt_printf(sess->fd, "Text=%lx;Data=%lx;Bss=%lx",
			sess->baseaddr, sess->baseaddr, sess->baseaddr);
}


/**
 * Input pattern 'qSupported:feature1;feeature2;...'
 *
 * Tell the remote stub about features supported by GDB, and query the stub for
 * features it supports. This packet allows GDB and the remote stub to take
 * advantage of each others’ features. ‘qSupported’ also consolidates multiple
 * feature probes at startup, to improve GDB performance—a single larger packet
 * performs better than multiple smaller probe packets on high-latency links.
 * Some features may enable behavior which must not be on by default, e.g.
 * because it would confuse older clients or stubs. Other features may describe
 * packets which could be automatically probed for, but are not. These features
 * must be reported before GDB will use them. This "default unsupported"
 * behavior is not appropriate for all packets, but it helps to keep the
 * initial connection time under control with new versions of GDB which support
 * increasing numbers of packets.
 *
 * Reply:
 *   feature1;feeature2;...;featureN
 *
 * The stub supports or does not support each returned stubfeature, depending
 * on the form of each stubfeature (see manual for the possible forms).
 **/
static int
gdb_response_supported(gdb_session_t* sess, const char* data, size_t size) {
  char s[0x100];

  sprintf(s, "PacketSize=%x", GDB_PKT_MAX_SIZE);
  strcat(s, ";qXfer:features:read+");

  return gdb_pkt_puts(sess->fd, s);
}


/**
 * Input pattern: 'qXfer:features:read:annex:offset,length'
 *
 * Access the target description. See Target Descriptions. The annex specifies
 * which XML document to access. The main description is always loaded from the
 * 'target.xml' annex.
 *
 * This packet is not probed by default; the remote stub must request it,
 * by supplying an appropriate ‘qSupported’ response (see qSupported).
 **/
static int
gdb_response_transfer(gdb_session_t* sess, const char* data, size_t size) {
  if(STR_START_WITH(data, "qXfer:features:read:target.xml:")) {
    return gdb_pkt_printf(sess->fd, "l%s", target_xml);
  }

  return gdb_pkt_printf(sess->fd, "");
}


/**
 * Input pattern: 's [addr]'
 *
 * Single step, resuming at addr. If addr is omitted, resume at same address.
 *
 * This packet is deprecated for multi-threading support. See vCont packet.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 *
 * -----------------------------------------------------------------------------
 *
 * Input pattern: 'S sig[;addr]'
 *
 * Step with signal. This is analogous to the 'C' packet, but requests a
 * single-step, rather than a normal resumption of execution.
 *
 * This packet is deprecated for multi-threading support. See vCont packet.
 *
 * Reply:
 *   See Stop Reply Packets, for the reply specifications.
 **/
static int
gdb_response_step(gdb_session_t* sess, const char* data, size_t size) {
  intptr_t addr = 0;
  char buf[32];
  int sig = 0;

  gdb_parse_stepcont(data, &addr, &sig);
  sig = gdb_sig_toposix(sig);

  // Never re-inject the signals that typically cause a stop; step
  // without a signal instead.
  if(SIGSTOP == sig || SIGTRAP == sig) {
    sig = 0;
  }

  if(gdb_step(sess->pid, addr, sig)) {
    return gdb_pkt_perror(sess->fd, "gdb_step");
  }

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 * Input pattern: 'vAttach;pid'
 *
 * Attach to a new process with the specified process ID pid. The process ID
 * is a hexadecimal integer identifying the process. In all-stop mode, all
 * threads in the attached process are stopped; in non-stop mode, it may be
 * attached without being stopped if that is supported by the target.
 *
 * This packet is only available in extended mode (see extended mode).
 *
 * Reply:
 *   'Any stop packet' - for success in all-stop mode (see Stop Reply Packets)
 *   ‘OK’ - for success in non-stop mode (see Remote Non-Stop) 
 **/
static int
gdb_response_attach(gdb_session_t* sess, const char* data, size_t size) {
  unsigned int upid;
  char buf[32];
  pid_t pid;

  if(sscanf(data, "vAttach;%x", &upid) != 1) {
    return gdb_pkt_puts(sess->fd, "");
  }

  pid = (pid_t)upid;
  if(gdb_attach(pid)) {
    return gdb_pkt_perror(sess->fd, "gdb_attach");
  }

  sess->pid = pid;
  sess->attached = 1;
  sess->sig = SIGTRAP;
  sess->code = 0;
  sess->stdio = -1;

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    sess->pid = -1;
    sess->attached = 0;
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}


/**
 * Input pattern: 'vFile:setfs:pid'
 *
 * Select the filesystem on which vFile operations with filename arguments will
 * operate. This is required for GDB to be able to access files on remote
 * targets where the remote stub does not share a common filesystem with the
 * inferior(s).
 *
 * If pid is nonzero, select the filesystem as seen by process pid. If pid is
 * zero, select the filesystem as seen by the remote stub. Return 0 on success,
 * or -1 if an error occurs. If vFile:setfs: indicates success, the selected
 * filesystem remains selected until the next successful vFile:setfs: operation.
 **/
static int
gdb_response_setfs(gdb_session_t* sess, const char* data, size_t size) {
  return gdb_pkt_puts(sess->fd, "F0");
}


/**
 * Input pattern: 'vFile:open: filename, flags, mode'
 *
 * Open a file at filename and return a file descriptor for it, or return -1
 * if an error occurs. The filename is a string, flags is an integer indicating
 * a mask of open flags (see Open Flags), and mode is an integer indicating a
 * mask of mode bits to use if the file is created (see mode_t Values).
 * See open, for details of the open flags and mode values.
 **/
static int
gdb_response_fsopen(gdb_session_t* sess, const char* data, size_t size) {
  char filename[PATH_MAX];
  char buf[PATH_MAX*2];
  const char* p;
  char *tok;
  unsigned int flags;
  unsigned int mode;
  int fd;

  if(strncmp(data, "vFile:open:", 11)) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }
  p = data + 11;

  if(strlen(p) >= sizeof(buf)) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }
  strcpy(buf, p);
  if(!(tok=strstr(buf, ","))) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }
  *tok = 0;

  if(gdb_hex2bin(buf, filename, sizeof(filename))) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }
  if(sscanf(tok+1, "%x,%x", &flags, &mode) != 2) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }

  // The protocol defines portable open flag values (O_CREAT=0x200,
  // O_TRUNC=0x400, ...); these are identical to the BSD ones used by
  // the PS4/PS5 firmware, so no translation is required here.
  if((fd=open(filename, flags, mode)) < 0) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)errno);
  }

  return gdb_pkt_printf(sess->fd, "F%x", (unsigned int)fd);
}


/**
 * Input pattern: 'vFile:close: fd'
 *
 * Close the open file corresponding to fd and return 0, or -1 if an
 * error occurs.
 **/
static int
gdb_response_fsclose(gdb_session_t* sess, const char* data, size_t size) {
  unsigned int fd;

  if(sscanf(data, "vFile:close:%x", &fd) != 1) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }

  if(close((int)fd)) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)errno);
  } else {
    return gdb_pkt_puts(sess->fd, "F0");
  }
}


/**
 * Input pattern: 'vFile:pwrite: fd, offset, data'
 *
 * Write data (a binary buffer) to the open file corresponding to fd. Start the
 * write at offset from the start of the file. Unlike many write system calls,
 * there is no separate count argument; the length of data in the packet is
 * used. 'vFile:pwrite' returns the number of bytes written, which may be
 * shorter than the length of data, or -1 if an error occurred.
 **/
static int
gdb_response_fswrite(gdb_session_t* sess, const char* data, size_t size) {
  const char* tok;
  ssize_t len;
  unsigned long off = 0;
  unsigned int fd;
  void* buf;
  int r;

  if(sscanf(data, "vFile:pwrite:%x,%lx", &fd, &off) != 2) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }

  if(!(tok=strstr(data, ","))) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }
  if(!(tok=strstr(tok+1, ","))) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }

  tok += 1;
  if((len=(ssize_t)(size-(size_t)(tok-data))) <= 0) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }
  if(!(buf=malloc(len))) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)ENOMEM);
  }

  memcpy(buf, tok, len);
  len = gdb_bin_unescape(buf, len);

  // Use pwrite() rather than lseek() + write(); the file descriptor may
  // be shared with other vFile operations.
  if((len=pwrite((int)fd, buf, len, (off_t)off)) == -1) {
    r = gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)errno);
  } else {
    r = gdb_pkt_printf(sess->fd, "F%x", (unsigned int)len);
  }

  free(buf);

  return r;
}


/**
 * Input pattern: 'vFile:pread: fd, count, offset'
 *
 * Read data (up to count bytes) from the open file corresponding to fd to
 * a buffer; start the read at offset from the start of the file.
 *
 * Reply:
 *   'F<count>;<data>' - count is the number of bytes read (in hex, 0 at
 *                       end of file), followed by the binary data.
 *   'F-1,<errno>'     - on failure.
 **/
static int
gdb_response_fsread(gdb_session_t* sess, const char* data, size_t size) {
  char head[16];
  unsigned long off = 0;
  unsigned int count = 0;
  unsigned int fd;
  ssize_t len;
  size_t head_len;
  size_t total;
  char* buf;
  char* out;
  int r;

  if(sscanf(data, "vFile:pread:%x,%x,%lx", &fd, &count, &off) != 3) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)EINVAL);
  }

  // Keep the reply below the packet size we advertise; binary data is
  // escaped on the wire (which may double its size), and there is room
  // needed for the leading 'F<count>;' header.
  if(count > (GDB_PKT_MAX_SIZE / 4)) {
    count = GDB_PKT_MAX_SIZE / 4;
  }

  if(!(buf=malloc(count ? count : 1))) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)ENOMEM);
  }

  if((len=pread((int)fd, buf, count, (off_t)off)) < 0) {
    free(buf);
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)errno);
  }

  // Reply format: 'F' <count in hex> ';' <binary data>. Escaping of the
  // binary data is applied by gdb_pkt_put().
  snprintf(head, sizeof(head), "F%x;", (unsigned int)len);
  head_len = strlen(head);
  total = head_len + (size_t)len;

  if(!(out=malloc(total))) {
    free(buf);
    return gdb_pkt_printf(sess->fd, "F-1,%x", (unsigned int)ENOMEM);
  }

  memcpy(out, head, head_len);
  memcpy(out + head_len, buf, len);

  free(buf);
  r = gdb_pkt_put(sess->fd, out, total);
  free(out);

  return r;
}


/**
 * Input pattern: 'vRun;filename[;argument]...'
 *
 * Run the program filename, passing it each argument on its command line.
 * The file and arguments are hex-encoded strings. If filename is an empty
 * string, the stub may use a default program (e.g. the last program run).
 * The program is created in the stopped state.
 *
 * This packet is only available in extended mode (see extended mode).
 *
 * Reply:
     Any stop packet for success (see Stop Reply Packets).
 **/
static int
gdb_response_run(gdb_session_t* sess, const char* data, size_t size) {
  char buf[PATH_MAX*2];
  char filename[PATH_MAX];
  char* argv[] = {filename, 0};
  const char *field, *end;
  size_t len;
  int fds[2];

  if(!(field=strchr(data, ';'))) {
    return gdb_pkt_printf(sess->fd, "E%02X", (EINVAL & 0xff));
  }
  field += 1;

  // Only the first argument is the program file; the remaining ';'-separated
  // fields are command line arguments. The ELF loader passes no arguments to
  // the payload, so they are ignored here.
  if(!(end=strchr(field, ';'))) {
    end = field + strlen(field);
  }
  len = end - field;

  if(!len) {
    // Empty filename: reuse the program from the previous vRun, if any.
    if(!sess->runfile[0]) {
      return gdb_pkt_printf(sess->fd, "E%02X", (ENOENT & 0xff));
    }
    memcpy(filename, sess->runfile, sizeof(filename));
  } else {
    if(len >= sizeof(buf)) {
      return gdb_pkt_printf(sess->fd, "E%02X", (EINVAL & 0xff));
    }
    memcpy(buf, field, len);
    buf[len] = 0;
    if(gdb_hex2bin(buf, filename, sizeof(filename))) {
      return gdb_pkt_printf(sess->fd, "E%02X", (EINVAL & 0xff));
    }
    snprintf(sess->runfile, sizeof(sess->runfile), "%s", filename);
  }

  // Clean up any inferior left from a previous run.
  gdb_halt_inferior(sess);

  if(pipe(fds) == -1) {
    return gdb_pkt_perror(sess->fd, "pipe");
  }

  if(fcntl(fds[0], F_SETFL, O_NONBLOCK) == -1){
    close(fds[0]);
    close(fds[1]);
    return gdb_pkt_perror(sess->fd, "fcntl");
  }

  if((sess->pid=gdb_spawn(argv, fds[1], &sess->baseaddr)) < 0) {
    close(fds[0]);
    close(fds[1]);
    return gdb_pkt_perror(sess->fd, "gdb_spawn");
  }

  close(fds[1]);
  sess->attached = 0;
  sess->sig = SIGSTOP;
  sess->code = 0;
  sess->stdio = fds[0];

  printf("Attached to PID: %d, ELF: %s\n", sess->pid, filename);

  return gdb_pkt_printf(sess->fd, "S%02X", gdb_sig_fromposix(sess->sig));
}


static int
gdb_response(void* ctx, const char* data, size_t size) {
  gdb_session_t* sess = (gdb_session_t*)ctx;

  switch(data[0]) {
  case '!':
    return gdb_response_extended_mode(sess, data, size);

  case '?':
    return gdb_response_getsig(sess, data, size);

  case 'c':
  case 'C':
    return gdb_response_continue(sess, data, size);

  case 'D':
    return gdb_response_detach(sess, data, size);

  case 'g':
    return gdb_response_getregs(sess, data, size);

  case 'G':
    return gdb_response_setregs(sess, data, size);

  case 'k':
    return gdb_response_kill(sess, data, size);

  case 'm':
    return gdb_response_getmem(sess, data, size);

  case 'M':
    return gdb_response_setmem(sess, data, size);

  case 'p':
    return gdb_response_getreg(sess, data, size);

  case 'P':
    return gdb_response_setreg(sess, data, size);

  case 'q':
    if(STR_START_WITH(data, "qAttached")) {
      return gdb_response_attached(sess, data, size);
    }
    if(!strcmp(data, "qOffsets")) {
      return gdb_response_offsets(sess, data, size);
    }
    if(STR_START_WITH(data, "qSupported")) {
      return gdb_response_supported(sess, data, size);
    }
    if(STR_START_WITH(data, "qXfer")) {
      return gdb_response_transfer(sess, data, size);
    }
    // We expose the inferior as a single thread whose id is its pid.
    // Without these replies gdb falls back to the obsolete 'qL' packet,
    // which crashes some gdb versions (e.g. 17.x).
    if(!strcmp(data, "qC")) {
      if(sess->pid > 0) {
	return gdb_pkt_printf(sess->fd, "QC%x", (unsigned int)sess->pid);
      }
      return gdb_pkt_puts(sess->fd, "");
    }
    if(!strcmp(data, "qfThreadInfo")) {
      if(sess->pid > 0) {
	return gdb_pkt_printf(sess->fd, "m%x", (unsigned int)sess->pid);
      }
      return gdb_pkt_puts(sess->fd, "l");
    }
    if(!strcmp(data, "qsThreadInfo")) {
      return gdb_pkt_puts(sess->fd, "l");
    }
    return gdb_pkt_puts(sess->fd, "");

  case 'H':
    // Set thread for subsequent operations; there is only one.
    return gdb_pkt_puts(sess->fd, "OK");

  case 'T':
    // Thread alive query.
    return gdb_pkt_puts(sess->fd, sess->pid > 0 ? "OK" : "E01");

  case 's':
  case 'S':
    return gdb_response_step(sess, data, size);

  case 'v':
    if(STR_START_WITH(data, "vAttach")) {
      return gdb_response_attach(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:setfs")) {
      return gdb_response_setfs(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:open")) {
      return gdb_response_fsopen(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:close")) {
      return gdb_response_fsclose(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:pwrite")) {
      return gdb_response_fswrite(sess, data, size);
    }
    if(STR_START_WITH(data, "vFile:pread")) {
      return gdb_response_fsread(sess, data, size);
    }
    if(STR_START_WITH(data, "vRun")) {
      return gdb_response_run(sess, data, size);
    }

    // unknown v-packets are answered with an empty reply
    /* fall through */
  default:
    return gdb_pkt_puts(sess->fd, "");
  }

  return -1;
}


void
gdb_response_session(int fd) {
  gdb_session_t sess = {
    .fd = fd,
    .pid = -1,
    .sig = 0,
    .stdio = -1,
    .baseaddr = 0
  };

  while(1) {
    if(gdb_pkt_get(fd, gdb_response, &sess)) {
      break;
    }
  }

  // The socket itself is closed by the connection handler thread; releasing
  // the interior (detaching attached processes, killing spawned ones) is
  // done here.
  gdb_halt_inferior(&sess);
}
