package disasm_cli

import "disasm"
import "formats/elf"

import "core:fmt"
import "core:os"
import "core:strings"

main :: proc() {
    bits := u8(64)
    is_elf  := true
    filenames := make([dynamic]string)
    for arg in os.args[1:] {
        if arg[0] == '-' {
            switch arg[1:] {
                case "16": bits = 16
                case "32": bits = 32
                case "64": bits = 64
                case "e":  is_elf = true
                case "r":  is_elf = false
                case:
                    fmt.eprintf("Unknown option: %s\n", arg)
                    os.exit(2)
            }
        } else {
            append(&filenames, arg)
        }
    }
    if !is_elf {
        for filename in filenames {
            bytes, ok := os.read_entire_file(filename)
            if !ok {
                fmt.eprintf("File %s: not able to read\n", filename)
                os.exit(1)
            }
            ctx := disasm.create_ctx(bytes, bits)
            builder := strings.builder_make()
            writer := strings.to_writer(&builder)
            for inst in disasm.disasm_inst(&ctx) {
                disasm.print_inst(inst, writer, true)
            }
            fmt.println(strings.to_string(builder))
        }
    } else {
        if len(filenames) > 1 || len(filenames) == 0 {
            fmt.eprintf("Please provide one file to disassemble\n")
            os.exit(2)
        }
        bytes, bytes_ok := os.read_entire_file(filenames[0])
        if !bytes_ok {
            fmt.eprintf("Unable to read file: %s\n", filenames[0])
            os.exit(1)
        }
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
        do_syms := false
        {
            ok := true
            sym_sec, _, sym_err := elf.section_by_name(file, ".symtab")
            str_sec, _, str_err := elf.section_by_name(file, ".strtab")
            if sym_err == nil {
                sym_data, symtab_err := elf.section_data(file, sym_sec, elf.Sym)
                assert(symtab_err == nil)
                #partial switch symtab_err {
                    case nil:
                        symtab = sym_data
                        fmt.println("Loaded the symbol table")
                    case: ok = false
                }
            } else {
                ok = false
            }
            if str_err == nil {
                str_data, strtab_err := elf.section_data(file, str_sec, u8)
                assert(strtab_err == nil)
                #partial switch strtab_err {
                    case nil:
                        strtab = str_data
                        fmt.println("Loaded the string table")
                    case: ok = false
                }
            } else {
                ok = false
            }
            if !ok {
                do_syms = false
            }
        }
        addr := text.addr
        ctx := disasm.create_ctx(text_bytes, bits)
        builder := strings.builder_make()
        writer := strings.to_writer(&builder)
        for inst in disasm.disasm_inst(&ctx) {
            if do_syms {
                found_sym := Maybe(elf.Sym) {}
                for sym in symtab {
                    type, bind := elf.symbol_info(sym)
                    if type == .Func {
                        if addr == sym.value {
                            found_sym = sym
                        }
                    }
                }
                if sym, ok := found_sym.?; ok {
                    sym_name := cast(cstring) cast([^]u8) &strtab[sym.name]
                    fmt.printf("\e[38;5;33m<%s>:\e[0m\n", sym_name)
                }
            }
            fmt.printf("  %012x ", addr)
            disasm.print_inst(inst, writer, true)
            addr += cast(uintptr) len(inst.bytes)
        }
        fmt.println(strings.to_string(builder))
        if ctx.offset < len(ctx.bytes) {
            fmt.printf("Error disassembling the byte: %02x (offset %016x)\n", ctx.bytes[ctx.offset], ctx.offset)
            fmt.printf("Context:\n")
            disasm.dump_bytes(ctx.bytes[max(0,ctx.offset-32):ctx.offset])
            fmt.printf("\e[38;5;210m%02x\e[0m ", ctx.bytes[ctx.offset])
            disasm.dump_bytes(ctx.bytes[ctx.offset+1:min(len(ctx.bytes), ctx.offset+32)])
            fmt.println()
            os.exit(1)
        }
    }
}
