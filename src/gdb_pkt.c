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
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gdb_pkt.h"


/**
 * Lookup table with the hex charset.
 **/
static const char hexchars[] = "0123456789abcdef";


/**
 *
 **/
static int
gdb_hex(int c) {
  return
    ((c >= 'a') && (c <= 'f')) ? c - 'a' + 10 :
    ((c >= '0') && (c <= '9')) ? c - '0' :
    ((c >= 'A') && (c <= 'F')) ? c - 'A' + 10 : -1;
}


/**
 * Write a character to the given file descriptor.
 **/
static int
gdb_putchar(int fd, char c) {
  while(1) {
    switch(write(fd, &c, sizeof(c))) {
    case -1:
      if(EAGAIN != errno && EINTR != errno) return -1;
      continue;
    case 0:
      return -1;
    default:
      return 0;
    }
  }
}


/**
 * Read a character form the given file descriptor.
 **/
static int
gdb_getchar(int fd) {
  char c;

  while(1) {
    switch(read(fd, &c, sizeof(c))) {
    case -1:
      if(EAGAIN != errno && EINTR != errno) return -1;
      continue;
    case 0:
      // EOF - the peer has closed the connection.
      errno = ECONNRESET;
      return -1;
    default:
      return (c & 0xff);
    }
  }
}


/**
 * Wait for the start symbol of a gdb packet.
 **/
static int
gdb_pkt_sync(int fd) {
  int c;
  while(1) {
    c = gdb_getchar(fd);
    switch(c) {
    case '$':
      return 0;
    case -1:
      return -1;
    default:
      continue;
    }
  }
}


/**
 * Emit a single $data#checksum sequence on the wire.
 **/
static int
gdb_pkt_send(int fd, const char* data, size_t size) {
  uint8_t checksum = 0;
  int ch;

  if(gdb_putchar(fd, '$')) {
    return -1;
  }

  for(size_t i=0; i<size; i++) {
    ch = data[i];
    if(('$' == ch) || ('#' == ch) || ('*' == ch) || ('}' == ch)) {
      ch ^= 0x20;
      checksum += (uint8_t)'}';
      if(gdb_putchar(fd, '}')) {
	return -1;
      }
    }
    checksum += ch;

    if(gdb_putchar(fd, ch)) {
      return -1;
    }
  }

  if(gdb_putchar(fd, '#')) {
    return -1;
  }
  if(gdb_putchar(fd, hexchars[checksum >> 4])) {
    return -1;
  }
  if(gdb_putchar(fd, hexchars[checksum % 16])) {
    return -1;
  }

  return 0;
}


int
gdb_pkt_put(int fd, const char* data, size_t size) {
  int attempt;

#if GDB_PKT_TRACE
  printf("rsp-out '%.*s'\n", (int)size, data);
#endif

  // Retransmit the packet a few times if the client responds with a NACK
  // ('-'), as mandated by the remote serial protocol.
  for(attempt=0; attempt<5; attempt++) {
    if(gdb_pkt_send(fd, data, size)) {
      return -1;
    }

    switch(gdb_getchar(fd)) {
    case 3:
      // Assume the client transmitted a Ctrl-c charcacter sequence
      // while an inferior is running.
      errno = EINTR;
      return -1;

    case '+':
      return 0;

    case '-':
      continue;

    default:
      errno = EPROTO;
      return -1;
    }
  }

  errno = EPROTO;
  return -1;
}


int
gdb_pkt_notify(int fd, const char* data, size_t size) {
  size_t buf_len = 1 + (2*size);
  char *buf;
  int r;

  if(!(buf=malloc(buf_len+1))) {
    return -1;
  }

  buf[0] = 'O';
  for(size_t i=0; i<size; i++) {
    sprintf(buf + 1 + (2*i), "%02x", (uint8_t)data[i]);
  }
  buf[buf_len] = 0;

  r = gdb_pkt_put(fd, buf, buf_len);
  free(buf);

  return r;
}


int
gdb_pkt_puts(int fd, const char* str) {
  return gdb_pkt_put(fd, str, strlen(str));
}


int
gdb_pkt_printf(int fd, const char *fmt, ...) {
  va_list args;
  char* s;
  int r;

  va_start(args, fmt);
  r = vasprintf(&s, fmt, args);
  va_end(args);

  if(r < 0) {
    return -1;
  }
  r = gdb_pkt_puts(fd, s);
  free(s);

  return r;
}


int
gdb_pkt_perror(int fd, const char *str) {
  int saved_errno = errno;

  // The 'E' reply only carries a two-digit hex error number. The textual
  // message cannot be sent as an 'O' packet here: 'O' is only valid while
  // gdb awaits a stop reply, and gdb would otherwise take it as the reply
  // to the current command, desynchronizing the session. Log it locally.
  fprintf(stderr, "%s: %s\n", str, strerror(saved_errno));

  return gdb_pkt_printf(fd, "E%02X", (saved_errno & 0xff));
}


int
gdb_pkt_notify_perror(int fd, const char *s) {
  char buf[0x200];

  snprintf(buf, sizeof(buf), "%s: %s", s, strerror(errno));

  return gdb_pkt_notify(fd ,buf, strlen(buf));
}


int
gdb_pkt_get(int fd, gdb_pkt_cb_t* cb, void* ctx) {
  uint8_t checksum = 0;
  uint8_t xmitcsum = 0;
  size_t offset = 0;
  char *buf = 0;
  int ch = 0;
  int nack = 0;
  int r;

  // One byte above the advertised PacketSize for the NUL terminator.
  if(!(buf=malloc(GDB_PKT_MAX_SIZE + 1))) {
    return -1;
  }

  while(1) {
    if(gdb_pkt_sync(fd)) {
      free(buf);
      return -1;
    }

    checksum = 0;
    offset = 0;

    while(1) {
      if((ch=gdb_getchar(fd)) == -1) {
	free(buf);
	return -1;
      }

      if('#' == ch) {
	break;
      }

      if(offset >= GDB_PKT_MAX_SIZE) {
	// Oversized packet (exceeds the advertised PacketSize): NACK it
	// and drop the session; this indicates a protocol violation or a
	// corrupt byte stream.
	gdb_putchar(fd, '-');
	free(buf);
	return -1;
      }

      checksum += (uint8_t)ch;
      buf[offset] = (char)ch;
      offset += 1;
    }
    buf[offset] = 0;

    if((ch=gdb_getchar(fd)) == -1) {
      free(buf);
      return -1;
    }
    xmitcsum = (uint8_t)(gdb_hex(ch) << 4);

    if((ch=gdb_getchar(fd)) == -1) {
      free(buf);
      return -1;
    }
    xmitcsum += (uint8_t)gdb_hex(ch);

    if(checksum != xmitcsum) {
      // Ask the client to retransmit; give up after a few consecutive
      // NACKs so a corrupt stream cannot hang the session.
      gdb_putchar(fd, '-');
      if(++nack >= 5) {
	free(buf);
	return -1;
      }
      continue;
    }

    break;
  }

#if GDB_PKT_TRACE
  printf("rsp-in '%.*s'\n", (int)offset, buf);
#endif

  gdb_putchar(fd, '+');
  r = cb(ctx, buf, offset);
  free(buf);
  return r;
}

