package disasm

import "core:fmt"

dump_bytes :: proc(bytes: []u8, row_size := 16) {
    for i in 0 ..< len(bytes) {
        fmt.printf("%02x ", bytes[i])
        if i != 0 && i % row_size == row_size-1 {
            fmt.print('\n')
        }
    }
}
