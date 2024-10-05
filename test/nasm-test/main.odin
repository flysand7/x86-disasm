package nasm_test

import "core:os/os2"
import "core:fmt"
import "core:strings"
import "core:strconv"
import "core:io"

import "disasm:disasm"

main :: proc() {
    if len(os2.args) != 2 {
        fmt.eprintfln("Error: expected 1 argument")
        os2.exit(1)
    }
    os2.mkdir_all("tmp/bin")
    state, stdout, stderr, err := os2.process_exec(os2.Process_Desc {
        command = []string {"nasm", os2.args[1], "-o", "tmp/bin/test-bytes"},
        env = os2.environ(context.allocator),
    }, context.allocator)
    if err != nil {
        fmt.eprintfln("Failed to run nasm: %v", err)
        os2.exit(1)
    }
    if state.exit_code != 0 {
        fmt.eprintfln("nasm returned bad error code: %d", state.exit_code)
        fmt.eprintfln("STDERR:\n%s", stderr)
        os2.exit(1)
    }
    asm_file, asm_file_err := os2.read_entire_file(os2.args[1], context.allocator)
    if asm_file_err != nil {
        fmt.eprintfln("Failed to read asm file '%s': %v", os2.args[1], asm_file_err)
        os2.exit(2)
    }
    bin_file, bin_file_err := os2.read_entire_file("tmp/bin/test-bytes", context.allocator)
    if bin_file_err != nil {
        fmt.eprintfln("Failed to read bin file '%s': %v", os2.args[1], asm_file_err)
        os2.exit(2)
    }
    instructions := bin_file
    addr := u64(0)
    cpu_mode := disasm.CPU_Mode.Mode_16
    line_no := 1
    for line in strings.split_lines_iterator(transmute(^string) &asm_file) {
        defer line_no += 1
        if len(line) == 0 || line[0] == ';' || line[len(line)-1] == ':'{
            continue
        }
        space_idx := strings.index_byte(line, ' ')
        if space_idx != -1 {
            if line[:space_idx] == "bits" {
                switch line[space_idx+1:] {
                case "16": cpu_mode = .Mode_16
                case "32": cpu_mode = .Mode_32
                case "64": cpu_mode = .Mode_64
                }
                continue
            }
            if line[:space_idx] == "cpu" {
                continue
            }
        }
        inst, ok := disasm.disasm_one(instructions[addr:])
        if !ok {
            fmt.eprintfln("Error: Failed to disassemble instruction at offset %#04x", addr)
            fmt.eprintfln("  Line: %d", line_no)
            fmt.eprintf("  First 8 bytes: [")
            for i in 0 ..< min(8, u64(len(instructions[addr:]))) {
                if i != 0 {
                    fmt.eprintf(" ")
                }
                fmt.eprintf("%02x", instructions[addr+i])
            }
            fmt.eprintfln("]")
            fmt.eprintfln("  Expected: %s", line)
            os2.exit(1)
        }
        sb := strings.builder_make()
        w := strings.to_writer(&sb)
        err := disasm.print_one(w, addr, inst, .Nasm)
        if err != nil {
            os2.exit(1)
        }
        io.flush(w)
        printed := strings.to_string(sb)
        if printed != line {
            fmt.eprintfln("Error: Disassembled instruction doesn't match the source at addr %#04x", addr)
            fmt.eprintfln("  Line: %d", line_no)
            fmt.eprintf("  Instruction bytes: [")
            for i in 0 ..< u64(inst.size) {
                if i != 0 {
                    fmt.eprintf(" ")
                }
                fmt.eprintf("%02x", instructions[addr+i])
            }
            fmt.eprintfln("]")
            fmt.eprintfln("  Printed:  %s", printed)
            fmt.eprintfln("  Expected: %s", line)
            os2.exit(1)
        }
        addr += u64(inst.size)
    }
    fmt.printfln("[SUCCESS] Test passed")
}