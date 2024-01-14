package disasm_cli

import "disasm"
import "formats/elf"

import "core:fmt"
import "core:os"
import "core:strings"
import "core:slice"
import "core:time"
import "core:io"

Obj_Format :: enum {
    Detect,
    Raw,
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
    print_flavor: Print_Flavor,
}

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
                os.exit(0)
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
            }
        } else if strings.has_prefix(arg, "-flavor:") {
            flavor := arg[8:]
            if flavor == "?" {
                fmt.println("Available flavors:")
                fmt.println("    -format:intel  Intel-style syntax")
                fmt.println("    -format:raw64  AT&T-style syntax")
                os.exit(0)
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
    disasm_file(&ctx, bytes)
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
        file, file_err := elf.file_from_bytes(bytes)
        if file_err != nil {
            fmt.eprintf("Elf reading error: %v\n", file_err)
            os.exit(1)
        }
        text, text_idx, text_err := elf.section_by_name(file, ".text")
        if text_err != nil {
            fmt.eprintf("Error finding .text section: %v\n", text_err)
            os.exit(1)
        }
        text_bytes, text_bytes_err := elf.section_data(file, text, u8)
        if text_bytes_err != nil {
            fmt.eprintf("Error reading .text section: %v\n", text_err)
            os.exit(1)
        }
        symtab := []elf.Sym {}
        strtab := []u8 {}
        do_syms := true
        if !ctx.force_no_syms {
            ok := true
            sym_sec, _, sym_err := elf.section_by_name(file, ".symtab")
            str_sec, _, str_err := elf.section_by_name(file, ".strtab")
            if sym_err == nil {
                sym_data, symtab_err := elf.section_data(file, sym_sec, elf.Sym)
                #partial switch symtab_err {
                    case nil:
                        symtab = sym_data
                        fmt.println("Loaded the symbol table")
                    case:
                        ok = false
                        fmt.println(".symtab section can't be loaded")
                }
            } else {
                ok = false
                fmt.println(".symtab wasn't found")
            }
            if str_err == nil {
                str_data, strtab_err := elf.section_data(file, str_sec, u8)
                #partial switch strtab_err {
                    case nil:
                        strtab = str_data
                        fmt.println("Loaded the string table")
                    case:
                        ok = false
                        fmt.println(".strtab section can't be loaded")
                }
            } else {
                ok = false
                fmt.println(".strtab section wasn't found")
            }
            if !ok {
                do_syms = false
            }
        } else {
            do_syms = false
        }
        if ctx.function != nil && do_syms == false {
            fmt.eprintln("Unable to do symbol lookups.")
            os.exit(1)
        }
        if do_syms {
            disasm_elf(ctx, text_bytes, symtab, strtab)
        } else {
            disasm_elf_raw(ctx, text_bytes, text.addr)
        }
    }
}

disasm_raw :: proc(ctx: ^Ctx, bytes: []u8) {
    if !ctx.print_all {
        builder := strings.builder_make()
        writer := strings.to_writer(&builder)
        disasm_print_bytes(ctx, writer, 0, bytes)
        fmt.println(strings.to_string(builder))
    } else {
        disasm_print_bytes(ctx, os.stream_from_handle(os.stdout), 0, bytes)
    }
}

disasm_elf_raw :: proc(ctx: ^Ctx, bytes: []u8, addr: uintptr) {
    if !ctx.print_all {
        builder := strings.builder_make()
        writer := strings.to_writer(&builder)
        disasm_print_bytes(ctx, writer, addr, bytes)
        fmt.println(strings.to_string(builder))
    } else {
        disasm_print_bytes(ctx, os.stream_from_handle(os.stdout), addr, bytes)
    }
}

disasm_elf :: proc(ctx: ^Ctx, text_bytes: []u8, symtab: []elf.Sym, strtab: []u8) {
    builder: strings.Builder
    writer: io.Writer
    if !ctx.print_all {
        builder = strings.builder_make()
        writer = strings.to_writer(&builder)
    } else {
        writer = os.stream_from_handle(os.stdout)
    }
    symtab := slice.filter(symtab, proc(sym: elf.Sym) -> bool {
        type, _ := elf.symbol_info(sym)
        return type == .Func && sym.size > 0
    })
    slice.sort_by(symtab, proc (i, j: elf.Sym) -> bool {
        return i.value < j.value
    })
    start_addr := -1
    for sym, sym_idx in symtab {
        if sym.size == 0 {
            continue
        }
        if start_addr == -1 {
            start_addr = cast(int) sym.value
        }
        type, bind := elf.symbol_info(sym)
        sym_name := cast(string) cast(cstring) &strtab[sym.name]
        if func_name, ok := ctx.function.?; ok {
            if sym_name != func_name {
                continue
            }
        }
        sym_addr := cast(int) sym.value
        sym_size := cast(int) sym.size
        sym_offs_lo := sym_addr - start_addr
        sym_offs_hi := sym_addr - start_addr + sym_size
        fmt.wprintf(writer, "\e[38;5;33m<%s>:\e[0m\n", sym_name)
        if !disasm_print_bytes(
            ctx,
            writer,
            cast(uintptr) sym_addr,
            text_bytes[sym_offs_lo:sym_offs_hi],
        ) {
            break
        }
    }
    if !ctx.print_all {
        fmt.println(strings.to_string(builder))
    }
}

disasm_print_bytes :: proc(ctx: ^Ctx, w: io.Writer, addr: uintptr, bytes: []u8) -> bool {
    b := bytes
    addr := addr
    for {
        inst_len, inst_enc, inst_err := disasm.pre_decode(.Mode_64, b)
        if inst_err == .Trunc {
            fmt.eprintf("Error(%012x): Failed to pre-decode instruction\n", addr)
            print_disasm_failure_ctx(b, inst_len)
            return false
        } else if inst_err == .No_Encoding {
            fmt.eprintf("Error(%012x): Failed to find an encoding for instruction\n", addr)
            print_disasm_failure_ctx(b, inst_len)
            return false
        } else if inst_err == .Invalid {
            fmt.eprintf("Error(%012x): Instruction encoding was found invalid\n", addr)
            print_disasm_failure_ctx(b, inst_len)
            return false
        }
        inst, inst_ok := disasm.decode(.Mode_64, b[:inst_len], inst_enc)
        if !inst_ok {
            fmt.eprintf("Error(%012x): Failed to disassemble instruction: Error finding an encoding matching constraints\n", addr)
            print_disasm_failure_ctx(b, inst_len, false)
            return false
        }
        fmt.wprintf(w, "  %012x ", addr)
        fmt.wprintf(w, "\e[38;5;242m")
        for b in b[:inst_len] {
            fmt.wprintf(w, "%02x", b)
        }
        for i in 0 ..< 16-inst_len {
            fmt.wprintf(w, "  ")
        }
        fmt.wprintf(w, "\e[0m")
        if ctx.print_flavor == .Intel {
            disasm.inst_print_intel(inst, w, ctx.color)
        } else {
            disasm.inst_print_att(inst, w, ctx.color)
        }
        if inst_len == len(b) {
            return true
        }
        b = b[inst_len:]
        addr += cast(uintptr) inst_len
    }
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
