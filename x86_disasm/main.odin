package x86_disasm

import "core:fmt"
import "core:os"
import "cli"

HELP ::
`x86-disasm: An x86 disassembler.

  %s <file> [options...]

Options:
  -help   Print a help message
`

main :: proc() {
    mb_input_path := Maybe(string) {}
    args, options := cli.parse_args(os.args[1:])
    if len(args) == 0 {
        fmt.eprintfln(HELP, os.args[0])
        os.exit(2)
    }
    if "help" in options {
        fmt.printfln(HELP, os.args[0])
        os.exit(0)
    }
    input_path := args[0]
    if ! os.exists(input_path) {
        fmt.printfln("Error: file does not exist: '%s'", input_path)
        os.exit(0)
    }
    if os.is_dir(input_path) {
        fmt.printfln("Error: cannot disassemble directory: '%s'", input_path)
        os.exit(0)
    }
    fmt.printfln("Disassembling %s", input_path)
}
