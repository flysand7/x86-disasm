package disasm_cli

import "disasm"
import "elf"

import "core:fmt"
import "core:os"
import "core:strings"
import "core:runtime"
import "core:slice"
import "core:time"
import "core:io"

Obj_Format :: enum {
    Detect,
    Raw,
    Hex,
    Elf,
}

Print_Flavor :: enum {
    Intel,
    Att,
}

Ctx :: struct {
    cpu: disasm.CPU_Mode,
    format: Obj_Format,
    color: bool,
    force_no_syms: bool,
    function: Maybe(string),
    filename: string,
    print_all: bool,
    print_timings: bool,
    print_flavor: Print_Flavor,
    instruction_count: int,
    pre_decode_duration: time.Duration,
    decode_duration: time.Duration,
    total_duration: time.Duration,
}

HELP_STRING :: `x86 disasm - an x86 disassembler
Usage:
    x86-disasm [options] <file>

Options:
    -format:<format>    Override the file format detection. Try '-format:?'
    -flavor:<flavor>    Disassembly flavor. Either 'intel' or 'att'.
    -function:<name>    Only disassemble a function by the given name.
    -force-no-syns      Treat object formats as if they don't have a symbol table.
    -no-color           Do not produce colored output.

Less common options:
    -print-all          Use this in case the disassembler dies with an error.
                        will print every line of disassembly to stdout one by one
                        (slow) but makes the context of the error clearer.
    -print-timings      Print the timings of disassembly.

`

main :: proc() {
    ctx := Ctx {
        color = true,
        print_flavor = .Intel,
    }
    filename := Maybe(string) {}
    for arg in os.args[1:] {
        if strings.has_prefix(arg, "-format:") {
            format := arg[8:]
            if format == "?" {
                fmt.println("Available formats:")
                fmt.println("    -format:elf    ELF file (Executables, .so, .o)")
                // TODO: fmt.println("    -format:ar     Archive file (.a)")
                // TODO: fmt.println("    -format:pe     Windows portable executble (.exe or .dll) file")
                // TODO: fmt.println("    -format:coff   Windows object (.obj) file")
                // TODO: fmt.println("    -format:lib    Windows archive (.lib) file")
                fmt.println("    -format:raw16  16-bit raw binary file")
                fmt.println("    -format:raw32  32-bit raw binary file")
                fmt.println("    -format:raw64  64-bit raw binary file")
                fmt.println("    -format:hex6  16-bit raw hex file")
                fmt.println("    -format:hex2  32-bit raw hex file")
                fmt.println("    -format:hex4  64-bit raw hex file")
                os.exit(2)
            }
            switch format {
                case "elf64":
                    ctx.format = .Elf
                    ctx.cpu = .Mode_64
                case "elf32":
                    ctx.format = .Elf
                    ctx.cpu = .Mode_32
                case "raw16":
                    ctx.format = .Raw
                    ctx.cpu = .Mode_16
                case "raw32":
                    ctx.format = .Raw
                    ctx.cpu = .Mode_32
                case "raw64":
                    ctx.format = .Raw
                    ctx.cpu = .Mode_64
                case "hex16":
                    ctx.format = .Hex
                    ctx.cpu = .Mode_16
                case "hex32":
                    ctx.format = .Hex
                    ctx.cpu = .Mode_32
                case "hex64":
                    ctx.format = .Hex
                    ctx.cpu = .Mode_64
            }
        } else if strings.has_prefix(arg, "-flavor:") {
            flavor := arg[8:]
            if flavor == "?" {
                fmt.println("Available flavors:")
                fmt.println("    -format:intel  Intel-style syntax")
                fmt.println("    -format:raw64  AT&T-style syntax")
                os.exit(2)
            }
            switch flavor {
                case "intel": ctx.print_flavor = .Intel
                case "att": ctx.print_flavor = .Att
                case: fmt.eprintf("Unknown flavor: %s\n", flavor)
            }
        } else if strings.has_prefix(arg, "-function:") {
            ctx.function = arg[10:]
        } else if arg == "-no-color" {
            ctx.color = false
        } else if arg == "-force-no-syms" {
            ctx.force_no_syms = true
        } else if arg == "-print-all" {
            ctx.print_all = true
        } else if arg == "-print-timings" {
            ctx.print_timings = true
        } else if arg == "-h" || arg == "-help" || arg == "--help" {
            fmt.printf("%s\n", HELP_STRING)
            os.exit(2)
        } else if arg[0] == '-' {
            fmt.eprintf("Unknown option: %s\n", arg)
            os.exit(2)
        } else {
            ctx.filename = arg
        }
    }
    bytes, bytes_ok := os.read_entire_file(ctx.filename)
    if !bytes_ok {
        fmt.eprintf("Unable to read file: %s\n", ctx.filename)
        os.exit(1)
    }
    saved_ctx = context
    disasm_file(&ctx, bytes)
}

saved_ctx: runtime.Context

stream_from_builder :: proc(b: ^strings.Builder) -> disasm.Stream {
    return {
        data = b,
        procedure = proc "c" (ctx: rawptr, buf_len: int, buf: [^]u8) {
            context = saved_ctx
            builder := cast(^strings.Builder) ctx
            strings.write_bytes(builder, buf[:buf_len])
        },
    }
}

disasm_file :: proc(ctx: ^Ctx, bytes: []u8) {
    if ctx.format == .Detect {
        if len(bytes) >= 4 &&
            bytes[0] == '\x7f' &&
            bytes[1] == 'E' &&
            bytes[2] == 'L' &&
            bytes[3] == 'F'
        {
            ctx.cpu = .Mode_64
            ctx.format = .Elf
        }
    }
    if ctx.format == .Raw {
        disasm_raw(ctx, bytes)
    } else if ctx.format == .Elf {
        disasm_elf_file(ctx, bytes)
    } else if ctx.format == .Hex {
        disasm_hex(ctx, bytes)
    }
    if ctx.print_timings {
        fmt.printf("Timings:\n")
        fmt.printf("  Instruction count: %v\n", ctx.instruction_count)
        fmt.printf("  Pre-decode time: %v (%v / instruction)\n",
            ctx.pre_decode_duration,
            ctx.pre_decode_duration / time.Duration(ctx.instruction_count),
        )
        fmt.printf("  Decode time:     %v (%v / instruction)\n",
            ctx.decode_duration,
            ctx.decode_duration / time.Duration(ctx.instruction_count),
        )
        fmt.printf("  Total time:      %v (%v / instruction)\n",
            ctx.total_duration,
            ctx.total_duration / time.Duration(ctx.instruction_count),
        )
    }
}

disasm_print_bytes :: proc(ctx: ^Ctx, s: ^disasm.Stream, addr: uintptr, bytes: []u8) -> bool {
    b := bytes
    addr := addr
    for {
        start_time := time.now()
        inst_len, inst_enc, inst_err := disasm.pre_decode(.Mode_64, b)
        ctx.pre_decode_duration += time.diff(start_time, time.now())
        if inst_err == .Trunc {
            disasm.stream_flush(s)
            fmt.eprintf("Error(%012x): Failed to pre-decode instruction\n", addr)
            print_disasm_failure_ctx(b, inst_len)
            return false
        } else if inst_err == .No_Encoding {
            disasm.stream_flush(s)
            fmt.eprintf("Error(%012x): Failed to find an encoding for instruction\n", addr)
            print_disasm_failure_ctx(b, inst_len)
            return false
        } else if inst_err == .Invalid {
            disasm.stream_flush(s)
            fmt.eprintf("Error(%012x): Instruction encoding was found invalid\n", addr)
            print_disasm_failure_ctx(b, inst_len)
            return false
        }
        decode_start_time := time.now()
        inst, inst_ok := disasm.decode(.Mode_64, b[:inst_len], inst_enc)
        ctx.decode_duration += time.diff(decode_start_time, time.now())
        if !inst_ok {
            disasm.stream_flush(s)
            fmt.eprintf("Error(%012x): Failed to disassemble instruction: Error finding an encoding matching constraints\n", addr)
            print_disasm_failure_ctx(b, inst_len, false)
            return false
        }
        disasm.stream_write_str(s, "  ")
        disasm.stream_write_hex(s, addr, 12)
        disasm.stream_write_str(s, " ")
        chars: [32]u8 = ' '
        if ctx.color {
            disasm.stream_write_str(s, "\e[38;5;242m")
        }
        hex := "0123456789abcdef"
        for b, i in b[:min(inst_len,15)] {
            chars[2*i+0] = hex[b/16]
            chars[2*i+1] = hex[b%16]
        }
        disasm.stream_write_str(s, transmute(string) chars[:])
        if ctx.color {
            disasm.stream_write_str(s, "\e[0m")
        }
        disasm.stream_write_str(s, " ")
        if ctx.print_flavor == .Intel {
            disasm.inst_print_intel(s, inst, ctx.color)
        } else {
            disasm.inst_print_att(s, inst, ctx.color)
        }
        if inst_len == len(b) {
            break
        }
        b = b[inst_len:]
        addr += cast(uintptr) inst_len
        ctx.total_duration += time.diff(start_time, time.now())
        ctx.instruction_count += 1
    }
    disasm.stream_flush(s)
    return true
}

print_disasm_failure_ctx :: proc(b: []u8, off: int, highlight := false) {
    fmt.eprintf("Context:\n")
    fmt.eprintf("  \e[31m")
    for i in 0 ..< min(len(b), 15) {
        if highlight && i == off {
            fmt.eprintf("\e[33m")
        }
        if i == off+1 {
            fmt.eprintf("\e[0m")
        }
        fmt.eprintf("%02x", b[i])
    }
    fmt.eprintf("\e[0m\n")
}
