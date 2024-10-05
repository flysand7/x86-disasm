package table

import "core:fmt"

print_flags :: proc(flags: Flags) {
    if .D in flags {
        fmt.printf("+d")
    }
}

print_entry :: proc(entry: Entry) {
    fmt.printf("(%d) %s %.2x", entry.src_line, entry.mnemonic, entry.opcode)
    #partial switch entry.encoding_kind {
    case .Mod_Rm:    fmt.printf("/rm")
    case .Rx_Extend: fmt.printf("/%d", entry.rx_value)
    case .Rx_Embed:  fmt.printf("+%d", entry.rx_value)
    }
    fmt.printf(" rx=%v", entry.rx_kind)
    if entry.rx_value != REG_NONE {
        if entry.encoding_kind == .Rx_Embed || entry.encoding_kind == .None {
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

print_entry_detailed :: proc(entry: Entry) {
    fmt.printfln(" Instruction: %s", entry.mnemonic)
    fmt.printfln(" Line: %d", entry.src_line)
    fmt.printf(" Opcode: %.2x", entry.opcode)
    #partial switch entry.encoding_kind {
    case .Mod_Rm:    fmt.printf("/rm")
    case .Rx_Extend: fmt.printf("/%d", entry.rx_value)
    }
    fmt.println("\n Operands:")
    if entry.encoding_kind == .Rx_Embed {
        fmt.printfln("   RX:  %v(%d)", entry.rx_kind, entry.rx_value)
    } else {
        fmt.printfln("   RX:  %v", entry.rx_kind)
    }
    fmt.printfln("   RM:  %v", entry.rx_kind)
    fmt.printfln("   EOP: %v", entry.eop)
    if entry.force_ds == DS_DEFAULT {
        fmt.printfln("   DS:  Default")
    } else {
        fmt.printfln("   DS:  %d bits", 8*entry.force_ds)
    }
    if entry.flags >= {.D} {
        fmt.printfln("   Order: RX, RM, EOP")
    } else {
        fmt.printfln("   Order: RM, RX, EOP")
    }
}
