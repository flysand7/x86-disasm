package disasm_cli

import "disasm"
import "formats/elf"

import "core:fmt"
import "core:os"

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
            for inst in disasm.disasm_inst(&ctx) {
                disasm.print_inst(inst, true)
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
        ctx := disasm.create_ctx(text_bytes, bits)
        for inst in disasm.disasm_inst(&ctx) {
            disasm.print_inst(inst, true)
        }
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
