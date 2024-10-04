package x86_disasm

import "core:io"

Syntax_Variant :: enum {
    Intel,
    ATT,
    Nasm,
}

print_one :: proc(w: io.Writer, inst: Instruction, syntax: Syntax_Variant) -> io.Error {
    switch syntax {
        case .Intel: return print_intel(w, inst)
        case .ATT: return print_att(w, inst)
        case .Nasm: return print_nasm(w, inst)
        case: panic("Unexpected syntax variant supplied.")
    }
    return .None
}

print_all :: proc(w: io.Writer, insts: []Instruction, syntax: Syntax_Variant) -> (err: io.Error) {
    for inst in insts {
        print_one(w, inst, syntax) or_return
        io.write_byte(w, '\n') or_return
    }
    return .None
}
