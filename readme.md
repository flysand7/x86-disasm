# x86-disasm

Fast, small and multithreadable x86 disassembler CLI / library. Currently supports
all general purpose, SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2, AVX
and some AVX2 instructions.

![Screenshot of intel-style disassembly](/extras/screenshot-disasm-intel.png)

Although it's not quite ready for daily-driving, bug reports and contributions
are welcome. See building section below.

## Features

[x] Print using intel or AT&T syntax flavor.
[x] Disassemble a function with a specific name.
[x] Decoding can be parralelized.

### Formats

[x] Disassembling Raw files.
[x] Disassembling Hex strings.
[x] Disassembling ELF files (Linux).
[ ] Disassembling COFF/PE files (Windows).
[ ] Disassembling Mach-O files (Mac-OS).

### Instruction sets

[x] General purpose instructions.
[x] SSE instructions.
[x] SSE2 instructions.
[x] SSE3 instructions.
[x] SSSE3 instructions.
[x] SSE4.1 instructions.
[x] SSE4.2 instructions.
[x] AVX instructions.
[x] AVX2 instructions.
[x] MPX instructions.
[ ] FPU instructions.
[ ] AVX512 instructions.

## Benchmarks

Disassembling the `x86-disasm` executable, against objdump:

```sh
$ just time-cli-objdump
hyperfine -w 16 "./x86-disasm ./x86-disasm -no-color" "objdump -M intel -d -j .text ./x86-disasm" --output pipe
Benchmark 1: ./x86-disasm ./x86-disasm -no-color
  Time (mean ± σ):      22.2 ms ±   3.5 ms    [User: 16.5 ms, System: 4.6 ms]
  Range (min … max):    18.8 ms …  44.8 ms    92 runs
 
  Warning: Statistical outliers were detected. Consider re-running this benchmark on a quiet system without any interferences from other programs. It might help to use the '--warmup' or '--prepare' options.
 
Benchmark 2: objdump -M intel -d -j .text ./x86-disasm
  Time (mean ± σ):      99.1 ms ±  15.3 ms    [User: 84.6 ms, System: 5.7 ms]
  Range (min … max):    85.6 ms … 147.1 ms    32 runs
 
Summary
  ./x86-disasm ./x86-disasm -no-color ran
    4.46 ± 0.98 times faster than objdump -M intel -d -j .text ./x86-disasm
```

My machine is pretty weak so there's some statistical anomalies that pop up.

Disassembling 1 million if statements (against ndisasm):

```sh
$ just time-cli-ndisasm
hyperfine -w 16 "./x86-disasm tests/is-even.bin -no-color -format:raw64" "ndisasm -b64 tests/is-even.bin" --output pipe

Benchmark 1: ./x86-disasm tests/is-even.bin -no-color -format:raw64
  Time (mean ± σ):      1.699 s ±  0.146 s    [User: 1.380 s, System: 0.174 s]
  Range (min … max):    1.568 s …  2.001 s    10 runs
 
Benchmark 2: ndisasm -b64 tests/is-even.bin
  Time (mean ± σ):      4.893 s ±  0.101 s    [User: 4.714 s, System: 0.088 s]
  Range (min … max):    4.772 s …  5.046 s    10 runs
 
Summary
  ./x86-disasm tests/is-even.bin -no-color -format:raw64 ran
    2.88 ± 0.26 times faster than ndisasm -b64 tests/is-even.bin
```

## Building

You will need a [just](https://github.com/casey/just) command runner to build
the disassembler cli. In case you don't want to install it, just copy commands
from `justfile` to your command line.

To build the CLI tool:

```sh
$ just build-cli-release
```

To build the library:

```sh
$ just build-lib
```

You can use the headers in `/include` directory to see the API of the library.


