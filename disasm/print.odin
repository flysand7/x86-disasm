package disasm

import "core:fmt"

@(private="file")
fmt_int :: proc(#any_int hex: i64) {
    sign_ch := '+'
    hex_abs := hex
    if hex < 0 {
        sign_ch = '-'
        hex_abs = -hex
    }
    if hex_abs < 10 {
        fmt.printf("%c%d", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u8) {
        fmt.printf("%c0x%02x", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u16) {
        fmt.printf("%c0x%04x", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u32) {
        fmt.printf("%c0x%08x", sign_ch, hex_abs)
    } else {
        fmt.printf("%c0x%016x", sign_ch, hex_abs)
    }
}

print_inst :: proc(inst: Inst) {
    WIDTH :: 10
    for i in 0 ..< len(inst.bytes) {
        fmt.printf("%02x", inst.bytes[i])
    }
    for i in len(inst.bytes) ..< WIDTH {
        fmt.printf("  ")
    }
    if .Lock in inst.flags {
        fmt.printf("lock ")
    }
    if .Rep in inst.flags {
        fmt.printf("rep ")
    }
    if .Repnz in inst.flags {
        fmt.printf("repnz ")
    }
    fmt.printf("%s", inst.mnemonic)
    if .Data_Size_Suffix in inst.flags {
        fmt.printf("%s", data_size_suffix(inst.data_size))
        if inst.mnemonic == "c" {
            fmt.printf("%s", data_size_suffix(2*inst.data_size))
        }
    }
    for i in 0 ..< inst.operands_count {
        fmt.printf(i != 0? ", " : " ")
        operand := inst.operands[i]
        switch op in operand {
            case Mem_Short:
                fmt.printf("short ")
                fmt_int(op.disp)
            case Mem:
                fmt.printf("%s ", data_size_spec(inst.data_size))
                if inst.seg_override != nil {
                    fmt.printf("%s:", sreg_name(inst.seg_override))
                }
                if selector, ok := inst.selector.?; ok {
                    fmt.printf("%02x:", selector)
                }
                fmt.printf("[")
                has_before := false
                if op.base.idx != nil {
                    fmt.printf("%s", reg_name(op.base))
                    has_before = true
                }
                if op.index.idx != nil {
                    fmt.printf("%s%d*%s", has_before?"+":"", op.scale, reg_name(op.index))
                }
                if op.disp != 0 {
                    fmt_int(op.disp)
                }
                fmt.printf("]")
            case Reg:
                fmt.printf("%s", reg_name(op))
            case MMX_Reg:
                fmt.printf("%s", mmxreg_name(op))
            case XMM_Reg:
                fmt.printf("%s", xmmreg_name(op))
            case Sreg:
                fmt.printf("%s", sreg_name(op))
            case Creg_Idx:
                fmt.printf("%s", creg_name(op))
            case Dreg_Idx:
                fmt.printf("%s", dreg_name(op))
            case Imm:
                fmt_int(op.value)
        }
    }
    fmt.printf("\n")
}

data_size_suffix :: proc(size: u8) -> string {
    switch size {
        case 8:  return "b"
        case 16: return "w"
        case 32: return "d"
        case 64: return "q"
        case: unreachable()
    }
}

data_size_spec :: proc(size: u8) -> string {
    switch size {
        case 8:  return "byte"
        case 16: return "word"
        case 32: return "dword"
        case 64: return "qword"
        case 128: return "xmmword"
        case: unreachable()
    }
}

granularity_suffix :: proc(gr: u8) -> string {
    switch gr {
        case 0b00: return "b"
        case 0b01: return "w"
        case 0b10: return "d"
        case 0b11: return "q"
        case: unreachable()
    }
}

sreg_name :: proc(sreg: Sreg) -> string {
    assert(sreg != nil)
    #partial switch sreg {
        case .Cs: return "cs"
        case .Ds: return "ds"
        case .Es: return "es"
        case .Fs: return "fs"
        case .Gs: return "gs"
        case .Ss: return "ss"
        case: unreachable()
    }
}

reg_name :: proc(reg: Reg) -> string {
    assert(reg.idx != nil)
    #partial switch reg.idx {
        case .Ax:
            switch reg.bits {
                case 8:  return "al"
                case 16: return "ax"
                case 32: return "eax"
                case 64: return "rax"
                case: unreachable()
            }
        case .Cx:
            switch reg.bits {
                case 8:  return "cl"
                case 16: return "cx"
                case 32: return "ecx"
                case 64: return "rcx"
                case: unreachable()
            }
        case .Bx:
            switch reg.bits {
                case 8:  return "bl"
                case 16: return "bx"
                case 32: return "ebx"
                case 64: return "rbx"
                case: unreachable()
            }
        case .Dx:
            switch reg.bits {
                case 8:  return "dl"
                case 16: return "dx"
                case 32: return "edx"
                case 64: return "rdx"
                case: unreachable()
            }
        case .Di:
            switch reg.bits {
                case 8:  return "ah"
                case 16: return "di"
                case 32: return "edi"
                case 64: return "rdi"
                case: unreachable()
            }
        case .Si:
            switch reg.bits {
                case 8:  return "ch"
                case 16: return "si"
                case 32: return "esi"
                case 64: return "rsi"
                case: unreachable()
            }
        case .Sp:
            switch reg.bits {
                case 8:  return "dh"
                case 16: return "sp"
                case 32: return "esp"
                case 64: return "rsp"
                case: unreachable()
            }
        case .Bp:
            switch reg.bits {
                case 8:  return "bh"
                case 16: return "bp"
                case 32: return "ebp"
                case 64: return "rbp"
                case: unreachable()
            }
        case .R8:
            switch reg.bits {
                case 8:  return "r8b"
                case 16: return "r8w"
                case 32: return "r8d"
                case 64: return "r8"
                case: unreachable()
            }
        case .R9:
            switch reg.bits {
                case 8:  return "r9b"
                case 16: return "r9w"
                case 32: return "r9d"
                case 64: return "r9"
                case: unreachable()
            }
        case .R10:
            switch reg.bits {
                case 8:  return "r10b"
                case 16: return "r10w"
                case 32: return "r10d"
                case 64: return "r10"
                case: unreachable()
            }
        case .R11:
            switch reg.bits {
                case 8:  return "r11b"
                case 16: return "r11w"
                case 32: return "r11d"
                case 64: return "r11"
                case: unreachable()
            }
        case .R12:
            switch reg.bits {
                case 8:  return "r12b"
                case 16: return "r12w"
                case 32: return "r12d"
                case 64: return "r12"
                case: unreachable()
            }
        case .R13:
            switch reg.bits {
                case 8:  return "r13b"
                case 16: return "r13w"
                case 32: return "r13d"
                case 64: return "r13"
                case: unreachable()
            }
        case .R14:
            switch reg.bits {
                case 8:  return "r14b"
                case 16: return "r14w"
                case 32: return "r14d"
                case 64: return "r14"
                case: unreachable()
            }
        case .R15:
            switch reg.bits {
                case 8:  return "r15b"
                case 16: return "r15w"
                case 32: return "r15d"
                case 64: return "r15"
                case: unreachable()
            }
        case .Ip:
            switch reg.bits {
                case 16: return "ip"
                case 32: return "eip"
                case 64: return "rip"
                case: unreachable()
            }
        case: unreachable()
    }
}

mmxreg_name :: proc(mmxreg: MMX_Reg) -> string {
    switch mmxreg {
        case .Mm7: return "mm7"
        case .Mm6: return "mm6"
        case .Mm5: return "mm5"
        case .Mm4: return "mm4"
        case .Mm3: return "mm3"
        case .Mm2: return "mm2"
        case .Mm1: return "mm1"
        case .Mm0: return "mm0"
        case: unreachable()
    }
}

xmmreg_name :: proc(xmmreg: XMM_Reg) -> string {
    switch xmmreg {
        case .Xmm0: return "xmm0"
        case .Xmm1: return "xmm1"
        case .Xmm2: return "xmm2"
        case .Xmm3: return "xmm3"
        case .Xmm4: return "xmm4"
        case .Xmm5: return "xmm5"
        case .Xmm6: return "xmm6"
        case .Xmm7: return "xmm7"
        case: unreachable()
    }
}

creg_name :: proc(creg: Creg_Idx) -> string {
    switch creg {
        case .Cr0: return "cr0"
        case .Cr1: return "cr1"
        case .Cr2: return "cr2"
        case .Cr3: return "cr3"
        case .Cr4: return "cr4"
        case .Cr5: return "cr5"
        case .Cr6: return "cr6"
        case .Cr7: return "cr7"
        case: unreachable()
    }
}

dreg_name :: proc(dreg: Dreg_Idx) -> string {
    switch dreg {
        case .Dr0: return "dr0"
        case .Dr1: return "dr1"
        case .Dr2: return "dr2"
        case .Dr3: return "dr3"
        case .Dr4: return "dr4"
        case .Dr5: return "dr5"
        case .Dr6: return "dr6"
        case .Dr7: return "dr7"
        case: unreachable()
    }
}

