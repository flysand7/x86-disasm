package tablegen

import "core:fmt"
import "core:os"
import "core:strconv"

import "disasm:arg"
import "disasm:table"

HELP_TEMPLATE ::
`table-gen: Table generator tool for x86-disasm.

Usage:
  %s <table.txt> <output.odin> [options...]

Options:
-help
    Print a help message
`

main :: proc() {
    args, options := arg.parse(os.args)
    if len(args) < 2 {
        fmt.eprintfln(HELP_TEMPLATE, os.args[0])
        os.exit(2)
    }
    if "help" in options {
        fmt.printfln(HELP_TEMPLATE, os.args[0])
        os.exit(0)
    }
    table_path := os.args[1]
    out_path := os.args[2]
    table_src, file_ok := os.read_entire_file(table_path)
    if !file_ok {
        fmt.eprintfln("Error reading '%s'", table_path)
        os.exit(1)
    }
    parsed_table := table.parse(string(table_src))
    if !output_tables(parsed_table, out_path){
        os.exit(1)
    }
}
