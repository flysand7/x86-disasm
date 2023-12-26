package disasm

import "core:os"
import "core:fmt"
import "core:testing"

dump_bytes :: proc(bytes: []u8, row_size := 16) {
    for i in 0 ..< len(bytes) {
        if i != 0 && i % row_size == 0 {
            fmt.print('\n')
        }
        fmt.printf("%02x ", bytes[i])
    }
    fmt.print('\n')
}

@(test)
test_dump :: proc(t: ^testing.T) {
    for arg in os.args[1:] {
        fmt.println()
        fmt.println(arg, ":", sep="")
        fmt.println("----------")
        file_bytes, file_bytes_ok := os.read_entire_file(arg)
        testing.expect_value(t, file_bytes_ok, true)
        dump_bytes(file_bytes)
    }
}
