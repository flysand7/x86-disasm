package disasm_cli

import "disasm"
import "formats/elf"

import "core:fmt"
import "core:os"
import "core:strings"
import "core:slice"

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
            if check_print_err(&ctx) {
                os.exit(1)
            }
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
        do_syms := true
        {
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
        }
        builder := strings.builder_make()
        writer := strings.to_writer(&builder)
        if !do_syms {
            ctx := disasm.create_ctx(text_bytes, bits)
            addr := text.addr
            for inst in disasm.disasm_inst(&ctx) {
                fmt.wprintf(writer, "  %012x ", addr)
                disasm.print_inst(inst, writer, true)
                addr += cast(uintptr) len(inst.bytes)
            }
            if check_print_err(&ctx) {
                os.exit(1)
            }
        } else {
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
                sym_addr := cast(int) sym.value
                sym_size := cast(int) sym.size
                sym_offs_lo := sym_addr - start_addr
                sym_offs_hi := sym_addr - start_addr + sym_size
                fmt.wprintf(writer, "\e[38;5;33m<%s>:\e[0m\n", sym_name)
                ctx := disasm.create_ctx(text_bytes[sym_offs_lo:sym_offs_hi], bits)
                addr := sym_addr
                for inst in disasm.disasm_inst(&ctx) {
                    fmt.wprintf(writer, "  %012x ", addr)
                    disasm.print_inst(inst, writer, true)
                    addr += len(inst.bytes)
                }
                if check_print_err(&ctx) {
                    os.exit(1)
                }
            }
        }
        fmt.println(strings.to_string(builder))
    }
}

check_print_err :: proc(ctx: ^disasm.Ctx) -> bool {
    if ctx.offset < len(ctx.bytes) {
        fmt.eprintf("Error disassembling the byte: %02x (offset %016x)\n", ctx.bytes[ctx.offset], ctx.offset)
        fmt.eprintf("Context:\n")
        disasm.dump_bytes(ctx.bytes[max(0,ctx.offset-32):ctx.offset])
        fmt.eprintf("\e[38;5;210m%02x\e[0m ", ctx.bytes[ctx.offset])
        disasm.dump_bytes(ctx.bytes[ctx.offset+1:min(len(ctx.bytes), ctx.offset+32)])
        fmt.eprintln()
        return true
    }
    return false
}
