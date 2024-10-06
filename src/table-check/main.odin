package table_check

import "core:os"
import "core:fmt"
import "disasm:table"

main :: proc() {
    if len(os.args) != 2 {
        fmt.eprintfln("Expected table argument")
        os.exit(2)
    }
    table_path := os.args[1]
    table_content, ok := os.read_entire_file(table_path)
    if !ok {
        fmt.eprintfln("Error: unable to read file: '%s'", table_path)
        os.exit(1)
    }
    entries := table.parse(transmute(string) table_content)
    for e1 in entries {
        if e1.encoding_kind == .Rx_Extend {
            if e1.rx_kind != .None {
                fmt.eprintfln("Error: Encoding can not have RX kind if its RX-extended")
                fmt.printf("Entry: ")
                table.print_entry(e1)
                os.exit(1)
            }
        }
        for e2 in entries {
            if e1.src_line == e2.src_line {
                continue
            }
            if e1.opcode != e2.opcode {
                continue
            }
            if e1.encoding_kind != e2.encoding_kind {
                fmt.eprintfln("Error: two encodings with the same opcode don't share encoding kind")
                fmt.printf("Entry 1: ")
                table.print_entry(e1)
                fmt.printf("Entry 2: ")
                table.print_entry(e2)
                os.exit(1)
            }
            encoding_kind := e1.encoding_kind
            if encoding_kind != .Rx_Extend {
                fmt.eprintfln("Error: intersection of opcodes (without rx-extend)")
                fmt.printf("Entry 1: ")
                table.print_entry(e1)
                fmt.printf("Entry 2: ")
                table.print_entry(e2)
                os.exit(1)
            }
            if e1.rx_value == e2.rx_value {
                fmt.eprintfln("Error: intersection of opcodes (with rx-extend)")
                fmt.printf("Entry 1: ")
                table.print_entry(e1)
                fmt.printf("Entry 2: ")
                table.print_entry(e2)
                os.exit(1)
            }
        }
    }
}