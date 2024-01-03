package disasm

import "core:os"
import "core:fmt"
import "core:testing"
import "core:strings"

@(test, private)
test_dump :: proc(t: ^testing.T) {
    for arg in os.args[1:] {
        fmt.println("----------")
        file_bytes, file_bytes_ok := os.read_entire_file(arg)
        testing.expect_value(t, file_bytes_ok, true)
        dump_bytes(file_bytes)
    }
}

@(test, private)
test_disasm :: proc(t: ^testing.T) {
    for arg in os.args[1:] {
        fmt.println("----------")
        file_bytes, file_bytes_ok := os.read_entire_file(arg)
        testing.expect_value(t, file_bytes_ok, true)
        ctx := create_ctx(file_bytes)
        builder := strings.builder_make()
        writer  := strings.to_writer(&builder)
        for inst in disasm_inst(&ctx) {
            print_inst(inst, writer)
        }
        fmt.println(strings.to_string(builder))
        if ctx.offset < len(ctx.bytes) {
            fmt.printf("Error disassembling the byte: %02x\n", ctx.bytes[ctx.offset])
            testing.fail_now(t)
        }
    }
}
