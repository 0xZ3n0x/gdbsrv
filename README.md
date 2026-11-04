# gdbsrv
This is a simple GDB server that can be executed on a Playstation 5 that has
been jailbroken and is running an ELF loader. The server accepts connections on
port 2159, and has been tested with gdb-15 and gdb-17.

## Building
Assuming you have the [ps5-payload-sdk][sdk-ps5] installed on a POSIX machine,
the GDB server can be compiled using the following two commands:
```console
john@localhost:gdbsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:gdbsrv$ make -f Makefile.ps5
```
The payload is written to `build/gdbsrv-ps5.elf`; send it to the ELF loader of
your PS5, e.g. `nc --send-only ps5 9021 < build/gdbsrv-ps5.elf`.

## Symbols for sony libraries
gdbsrv reports the loaded sony libraries to gdb, and builds a symbol file for
each of them on the target from the symbol table the kernel keeps for the
library. NIDs are translated to names using a table generated from the
payload SDK at build time. With gdb's default `sysroot` (`target:`) this works
out of the box; no files are needed on the host:
```
(gdb) set osabi none
(gdb) target extended-remote ps5:2159
```
Run `sharedlibrary` in gdb to pick up libraries loaded after startup.

## Known issues
- Only NIDs whose names are known to the payload SDK are translated; other
  library symbols show up under their NID.

## Reporting Bugs
If you encounter problems with gdbsrv, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
gdbsrv is licensed under the GPLv3+.

[sdk-ps5]: https://github.com/ps5-payload-dev/sdk
[issues]: https://github.com/ps5-payload-dev/shsrv/issues/new
