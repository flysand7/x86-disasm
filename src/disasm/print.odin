package x86_disasm

import "core:io"

Syntax_Variant :: enum {
    Intel,
    ATT,
    Nasm,
}

print_one :: proc(w: io.Writer, addr: u64, inst: Instruction, syntax: Syntax_Variant) -> io.Error {
    switch syntax {
        case .Intel: return print_intel(w, addr, inst)
        case .ATT: return print_att(w, addr, inst)
        case .Nasm: return print_nasm(w, addr, inst)
        case: panic("Unexpected syntax variant supplied.")
    }
    return .None
}
