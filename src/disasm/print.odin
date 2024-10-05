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

sreg_name :: proc(size: u8, reg: u8) -> string {
    if size == 2 {
        switch reg {
        case REG_ES: return "es"
        case REG_CS: return "cs"
        case REG_SS: return "ss"
        case REG_DS: return "ds"
        case REG_FS: return "fs"
        case REG_GS: return "gs"
        case: panic("Unknown register name found")
        }
    } else {
        panic("Registers of this size are not supported")
    }
}

gpreg_name :: proc(size: u8, reg: u8) -> string {
    if size == 1 {
        switch reg {
        case REG_AX: return "al"
        case REG_CX: return "cl"
        case REG_DX: return "dl"
        case REG_BX: return "bl"
        case REG_SP: return "ah"
        case REG_BP: return "ch"
        case REG_SI: return "dh"
        case REG_DI: return "bh"
        case: panic("Unknown register name found")
        }
    } else if size == 2 {
        switch reg {
        case REG_AX: return "ax"
        case REG_CX: return "cx"
        case REG_DX: return "dx"
        case REG_BX: return "bx"
        case REG_SP: return "sp"
        case REG_BP: return "bp"
        case REG_SI: return "si"
        case REG_DI: return "di"
        case: panic("Unknown register name found")
        }
    } else if size == 4 {
        switch reg {
        case REG_AX: return "eax"
        case REG_CX: return "ecx"
        case REG_DX: return "edx"
        case REG_BX: return "ebx"
        case REG_SP: return "esp"
        case REG_BP: return "ebp"
        case REG_SI: return "esi"
        case REG_DI: return "edi"
        case: panic("Unknown register name found")
        }
    } else {
        panic("Registers of this size are not supported")
    }
}

