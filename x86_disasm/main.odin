package x86_disasm

import "core:fmt"
import "core:os"

HELP ::
`x86-disasm: An x86 disassembler.
    x86-disasm <file> [options...]
Options:
-help   Print a help message
`

main :: proc() {
    if len(os.args) <= 1 {
        fmt.eprintfln(HELP)
        os.exit(2)
    }
    mb_input_path := Maybe(string) {}
    for arg in os.args {
        if arg == "-help" {
            fmt.printfln(HELP)
            os.exit(0)
        } else {
            mb_input_path = arg
        }
    }
    if mb_input_path == nil {
        fmt.eprintfln("Error: No input filename.")
        os.exit(2)
    }
    input_path := mb_input_path.?
    fmt.printfln("Disassembling %s", input_path)
}
