package hexdump

import "core:fmt"
import "core:os"

hex_digits := "0123456789abcdef"

main :: proc() {
    if len(os.args) < 2 {
        fmt.eprintfln("hexdump <filename>")
        os.exit(2)
    }
    bytes, ok := os.read_entire_file(os.args[1])
    if !ok {
        fmt.eprintfln("Unable to read file %s", os.args[1])
        os.exit(1)
    }
    for b, idx in bytes {
        if idx%8 == 0 && idx != 0 {
            fmt.println()
        }
        hi := hex_digits[b/16]
        lo := hex_digits[b%16]
        fmt.printf("%c%c ", hi, lo)
    }
}