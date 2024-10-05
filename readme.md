
# x86-disasm

![license](https://img.shields.io/github/license/flysand7/x86-disasm?style=for-the-badge)
![build](https://img.shields.io/github/actions/workflow/status/flysand7/x86-disasm/build.yml?branch=main&style=for-the-badge)
![issues](https://img.shields.io/github/issues/flysand7/x86-disasm?style=for-the-badge)

x86 is a minimal x86 disassembler, with the goal of providing the best user
experience when inspecting the executable files, providing the user with
various options to control how the disassembled output should be presented.

> [!IMPORTANT]
> x86-disasm is currently in development. It is currently not ready to be used
> on a daily basis and a lot of the functionality may unexpectedly break.

## Features

Supported platforms
- [x] Windows
- [x] Linux
- [ ] Mac-OS

File formats:

- [x] Raw
- [x] PE/COFF (windows `.exe`, `.dll` and `.obj` files)
- [x] ELF (linux executables and `.o` files)
- [ ] Mach-O

Output flavors:

- [x] Intel
- [ ] AT&T

CPU feature sets:

- [x] 8086
- [ ] 80186
- [ ] 80286
- [ ] 80386 (i386)
- [ ] Pentium 5/6 (i586/i686)
- [ ] x86-64
- [ ] x87 FPU
- [ ] MMX
- [ ] SSE
- [ ] SSE2
- [ ] SSE3
- [ ] SSSE3
- [ ] SSE4/4.1/4.2
- [ ] AVX
- [ ] AVX2

> [!NOTE]
> The support for AVX-512 and AMX is not planned, as those are large extensions
> that are rarely used on consumer PC's.

