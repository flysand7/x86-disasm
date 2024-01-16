package disasm_cli

import "disasm"
import "elf"

import "core:os"
import "core:fmt"
import "core:slice"
import "core:strings"

disasm_elf_file :: proc(ctx: ^Ctx, bytes: []u8) {
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

disasm_elf_raw :: proc(ctx: ^Ctx, bytes: []u8, addr: uintptr) {
    if !ctx.print_all {
        builder := strings.builder_make()
        stream := stream_from_builder(&builder)
        disasm_print_bytes(ctx, &stream, addr, bytes)
        fmt.println(strings.to_string(builder))
    } else {
        stream := disasm.make_stdout_stream()
        disasm_print_bytes(ctx, &stream, addr, bytes)
    }
}

disasm_elf :: proc(ctx: ^Ctx, text_bytes: []u8, symtab: []elf.Sym, strtab: []u8) {
    builder := strings.Builder {}
    stream := disasm.Stream {}
    if !ctx.print_all {
        builder = strings.builder_make()
        stream = stream_from_builder(&builder)
    } else {
        stream = disasm.make_stdout_stream()
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
        if ctx.color {
            disasm.stream_write_str(&stream, "\e[38;5;33m")
        }
        disasm.stream_write_str(&stream, "<")
        disasm.stream_write_str(&stream, sym_name)
        disasm.stream_write_str(&stream, ">:\n")
        if ctx.color {
            disasm.stream_write_str(&stream, "\e[0m")
        }
        if !disasm_print_bytes(
            ctx,
            &stream,
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
