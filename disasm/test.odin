package disasm

import "core:os"
import "core:fmt"
import "core:testing"

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
        for inst in disasm_inst(&ctx) {
            print_inst(inst)
        }
    }
}
