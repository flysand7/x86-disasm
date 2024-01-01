package disasm

import "core:fmt"

dump_bytes :: proc(bytes: []u8, row_size := 16) {
    for i in 0 ..< len(bytes) {
        if i != 0 && i % row_size == 0 {
            fmt.print('\n')
        }
        fmt.printf("%02x ", bytes[i])
    }
    fmt.print('\n')
}
