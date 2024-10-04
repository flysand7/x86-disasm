package table

import "core:fmt"

print_flags :: proc(flags: Flags) {
    if .D in flags {
        fmt.printf("+d")
    }
}

print_entry :: proc(entry: Entry) {
    fmt.printf("%s %.2x", entry.mnemonic, entry.opcode)
    #partial switch entry.encoding_kind {
    case .Mod_Rm:    fmt.printf("/")
    case .Rx_Extend: fmt.printf("/%d", entry.rx_value)
    case .Rx_Embed:  fmt.printf("^%d", entry.rx_value)
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
