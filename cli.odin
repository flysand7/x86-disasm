package disasm_cli

import "disasm"

import "core:fmt"
import "core:os"

main :: proc() {
    bits := u8(64)
    elf  := true
    filenames := make([dynamic]string)
    for arg in os.args[1:] {
        if arg[0] == '-' {
            switch arg[1:] {
                case "16": bits = 16
                case "32": bits = 32
                case "64": bits = 64
                case "e":  elf = true
                case "r":  elf = false
                case:
                    fmt.eprintf("Unknown option: %s\n", arg)
                    os.exit(2)
            }
        } else {
            append(&filenames, arg)
        }
    }
    if !elf {
        for filename in filenames {
            bytes, ok := os.read_entire_file(filename)
            if !ok {
                fmt.eprintf("File %s: not able to read\n", filename)
                os.exit(1)
            }
            ctx := disasm.create_ctx(bytes, bits)
            for inst in disasm.disasm_inst(&ctx) {
                disasm.print_inst(inst)
            }
        }
    } else {
        fmt.eprintf("ELF disassembely not supported yet\n")
        os.exit(2)
    }
}
