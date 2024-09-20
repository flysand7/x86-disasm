package tablegen

import "core:fmt"
import "core:os"
import "core:strconv"

HELP_TEMPLATE ::

`tablegen: Table generator tool for x86-disasm.
Usage:
  %s <table.txt> <output-dir> [options...]
Options:
  -help
      Print a help message
  -print
      Print the parsed table to stdout.
  -print:<mnemonic>
      Print all entries of the parsed table for specified mnemonic.
  -line:<number>
      Print the entry of the parsed table described on the specified line of
      the table.txt file.
`

print_mnemonic := ""
print_line := -1

print_flags :: proc(flags: bit_set[Table_Entry_Flag]) {
    if .D in flags {
        fmt.printf("+d")
    }
}

print_table :: proc(table: []Table_Entry) {
    for entry in table {
        line_matches := print_line == -1 || entry.src_line == print_line
        mnemonic_matches := print_mnemonic == "" || entry.mnemonic == print_mnemonic
        if line_matches && mnemonic_matches {
            fmt.printf("%s %.2x", entry.mnemonic, entry.opcode)
            #partial switch entry.opcode_kind {
            case .Normal:    fmt.printf("/")
            case .Rx_Extend: fmt.printf("/%d", entry.rx_value)
            case .Rx_Embed:  fmt.printf("^%d", entry.rx_value)
            }
            fmt.printf(" rx=%v", entry.rx_kind)
            if entry.rx_value != REG_NONE {
                if entry.opcode_kind == .Rx_Embed || entry.opcode_kind == .None {
                    fmt.printf("(%v)", entry.rx_value)
                } 
            }
            fmt.printf(" rm=%v", entry.rm_kind)
            if entry.eop != .None {
                fmt.printf(" eop=%v", entry.eop)
            }
            if entry.force_ds != DS_DEFAULT {
                fmt.printf(" ds=%v", entry.force_ds)
            }
            fmt.printf(" ")
            print_flags(entry.flags)
            fmt.println()
        }
    }
}

main :: proc() {
    args, options := parse_args(os.args)
    if len(args) < 2 {
        fmt.eprintfln(HELP_TEMPLATE, os.args[0])
        os.exit(2)
    }
    do_print_table := false
    if "help" in options {
        fmt.printfln(HELP_TEMPLATE, os.args[0])
        os.exit(0)
    }
    if "print" in options {
        value := options["print"]
        do_print_table = true
        if mnemonic, ok := value.(string); ok {
            print_mnemonic = mnemonic
        } else {
            fmt.eprintfln("The -print option doesn't take a key-value pair")
            os.exit(2)
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
            fmt.eprintfln("The -line option doesn't take a key-value pair")
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
    table := parse_table(string(table_src))
    if do_print_table {
        print_table(table)
    }
}
