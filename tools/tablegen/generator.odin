package tablegen

import "core:fmt"
import "core:os"

print_flags :: proc(flags: bit_set[Table_Entry_Flag]) {
    if .D in flags {
        fmt.printf("+d")
    }
}

print_table :: proc(table: []Table_Entry) {
    for entry in table {
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

main :: proc() {
    if len(os.args) < 3 {
        fmt.eprintfln("Error: invalid format")
        fmt.eprintfln("   ./tablegen path/to/table.txt output/path/")
        os.exit(1)
    }
    do_print_table := false
    for arg in os.args[3:] {
        switch arg {
        case "-print": do_print_table = true
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
