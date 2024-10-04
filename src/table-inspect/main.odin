package table_inspec

import "core:fmt"
import "core:os"
import "core:strconv"

import "disasm:arg"
import "disasm:table"

HELP_TEMPLATE ::
`table-inspect: Table inspector tool for x86-disasm.

Usage:
  %s <table.txt> [options...]

Options:
-help
    Print a help message
-mnemonic:<mnemonic>
    Print all entries of the parsed table for specified mnemonic.
-opcode:<byte>
    Print all entries with the specified first opcode byte.
-line:<number>
    Print the entry of the parsed table described on the specified line of
    the table.txt file.
`

main :: proc() {
    args, options := arg.parse(os.args[1:])
    if len(args) != 1 || "help" in options {
        fmt.eprintfln(HELP_TEMPLATE, os.args[0])
        os.exit(2)
    }
    print_mnemonic := ""
    print_opcode := -1
    print_line := -1
    if "mnemonic" in options {
        if val, ok := options["mnemonic"].(string); ok {
            print_mnemonic = val
        } else {
            fmt.eprintfln("The -mnemonic option expects a single value")
            os.exit(2)
        }
    }
    if "line" in options {
        if val, ok := options["line"].(string); ok {
            line, line_ok := strconv.parse_int(val, 10)
            if !line_ok {
                fmt.eprintfln("The -line option expects a decimal integer. '%s' is not a valid decimal integer.", val)
                os.exit(2)
            }
            print_line = line
        } else {
            fmt.eprintfln("The -line option expects a line number")
            os.exit(2)
        }
    }
    if "opcode" in options {
        if val, ok := options["opcode"].(string); ok {
            opcode, opcode_ok := strconv.parse_int(val, 16)
            if !opcode_ok {
                fmt.eprintfln("The -opcode option expects a hexadecimal integer. '%s' is not a valid hexadecimal integer", val)
                os.exit(2)
            }
            print_opcode = opcode
        } else {
            fmt.eprintfln("The -opcode option expects an opcode")
            os.exit(2)
        }
    }
    table_src, table_src_ok := os.read_entire_file(args[0])
    if !table_src_ok {
        fmt.eprintfln("Unable to read table path: '%s'.", args[0])
        os.exit(1)
    }
    n_printed := 0
    entries := table.parse(string(table_src))
    mt: table.Multistage_Tables = ---
    table.mt_init(&mt)
    for entry in entries {
        table.mt_add(&mt, entry)
        mnemonic_match := print_mnemonic == "" || entry.mnemonic == print_mnemonic
        line_match := print_line == -1 || entry.src_line == print_line
        opcode_match := print_opcode == -1 || int(entry.opcode) == print_opcode
        if mnemonic_match && line_match && opcode_match {
            fmt.printfln("+---------------------------------------------+")
            table.print_entry_detailed(entry)
            stage1 := mt.s1_table[entry.opcode]
            stage2: table.Stage2_Encoding
            stage2_idx := -1
            rx_stage: []int
            rx_stage_idx := -1
            if stage1.kind == .Rx_Extend {
                rx_stage_idx = stage1.entry_idx
                rx_stage = mt.rx_table[rx_stage_idx][:]
                stage2_idx = rx_stage[entry.rx_value]
                stage2 = mt.s2_table[stage2_idx]
            } else {
                stage2_idx = stage1.entry_idx
                stage2 = mt.s2_table[stage2_idx]
            }
            fmt.println(" Encoding:")
            if stage1.force_ds != table.DS_DEFAULT {
                fmt.printfln("   Stage 1 [%#.2x]->[%d] (eop: %v, ds: %v)", entry.opcode, stage1.entry_idx, stage1.eop, stage1.force_ds)
            } else {
                fmt.printfln("   Stage 1 [%#.2x]->[%d] (eop: %v)", entry.opcode, stage1.entry_idx, stage1.eop)
            }
            if rx_stage_idx != -1 {
                fmt.printfln("   RX stage [%d]->[%d]", rx_stage_idx, stage2_idx)
            }
            if stage2.rx_value != 0xff && stage1.kind != .Rx_Embed {
                fmt.printfln("   Stage 2 [%d] (%s: rx: %v(%d), rm: %v)", stage2_idx, stage2.mnemonic, stage2.rx_kind, stage2.rx_value, stage2.rm_kind)
            } else {
                fmt.printfln("   Stage 2 [%d] (%s: rx: %v, rm: %v)", stage2_idx, stage2.mnemonic, stage2.rx_kind, stage2.rm_kind)
            }
            n_printed += 1
        }
    }
    fmt.printfln("+---------------------------------------------+")
    fmt.printfln("Printed %d entries", n_printed)
}