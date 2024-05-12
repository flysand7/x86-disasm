package cli

import "core:fmt"
import "core:os"
import "pe"

HELP_TEMPLATE ::
`x86-disasm: An x86 disassembler.
Usage:
  %s <file> [options...]
Options:
  -help    Print a help message
  -verbose Print verbose messages
`

verbose_print := false

main :: proc() {
    mb_input_path := Maybe(string) {}
    args, options := parse_args(os.args[1:])
    if len(args) == 0 {
        fmt.eprintfln(HELP_TEMPLATE, os.args[0])
        os.exit(2)
    }
    if "help" in options {
        fmt.printfln(HELP_TEMPLATE, os.args[0])
        os.exit(0)
    }
    if "verbose" in options {
        verbose_print = true
    }
    input_path := args[0]
    // TODO(flysand): This line contains a TOCTOU bug. We should be checking
    // for error condition once we try to open a file and check if its a directory
    // using a file handle.
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
