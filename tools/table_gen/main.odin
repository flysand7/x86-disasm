package tablegen

import "core:fmt"
import "core:os"
import "core:strconv"

import "common:arg"
import "common:table"

HELP_TEMPLATE ::
`table-gen: Table generator tool for x86-disasm.

Usage:
  %s <table.txt> <output.odin> [options...]

Options:
-help
    Print a help message
-print
    Print the parsed table to stdout.
-print:<mnemonic>
    Print all entries of the parsed table for specified mnemonic.
-opcode:<byte>
    Print all entries with the specified first opcode byte.
-line:<number>
    Print the entry of the parsed table described on the specified line of
    the table.txt file.
`

do_print_table := false
print_mnemonic := ""
print_line := -1
print_opcode := -1

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
    if "print" in options {
        value := options["print"]
        do_print_table = true
        if value != nil {
            if mnemonic, ok := value.(string); ok {
                print_mnemonic = mnemonic
            } else {
                fmt.eprintfln("Bad format -print:<mnemonic> or just -print expected")
                os.exit(2)
            }
        }
    }
    if "line" in options {
        do_print_table = true
        if line, ok := options["line"].(string); ok {
            parsed_line, ok := strconv.parse_int(line)
            if !ok {
                fmt.eprintfln("The -line option expects a number")
                os.exit(2)
            }
            print_line = parsed_line-1
        } else {
            fmt.eprintfln("Bad format: -line:<number> expected")
            os.exit(2)
        }
    }
    if "opcode" in options {
        do_print_table = true
        if opcode, ok := options["opcode"].(string); ok {
            parsed_opcode, ok := strconv.parse_int(opcode, 16)
            if !ok {
                fmt.eprintfln("The -opcode option expects a hexadecimal number")
                os.exit(2)
            }
            if parsed_opcode <= 0 || parsed_opcode > 0xff {
                fmt.eprintfln("Opcode byte out of bounds")
                os.exit(2)
            }
            print_opcode = parsed_opcode
        } else {
            fmt.eprintfln("Bad format: -opcode:<byte> expected")
            os.exit(2)
        }
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
