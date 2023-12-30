package disasm

import "core:fmt"

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
                case 16: return "sp"
                case 32: return "esp"
                case 64: return "rsp"
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
                case 32: return "r8d"
                case 64: return "r8"
                case: unreachable()
            }
        case .R9:
            switch reg.bits {
                case 8:  return "r9b"
                case 32: return "r9d"
                case 64: return "r9"
                case: unreachable()
            }
        case .R10:
            switch reg.bits {
                case 8:  return "r10b"
                case 32: return "r10d"
                case 64: return "r10"
                case: unreachable()
            }
        case .R11:
            switch reg.bits {
                case 8:  return "r11b"
                case 32: return "r11d"
                case 64: return "r11"
                case: unreachable()
            }
        case .R12:
            switch reg.bits {
                case 8:  return "r12b"
                case 32: return "r12d"
                case 64: return "r12"
                case: unreachable()
            }
        case .R13:
            switch reg.bits {
                case 8:  return "r13b"
                case 32: return "r13d"
                case 64: return "r13"
                case: unreachable()
            }
        case .R14:
            switch reg.bits {
                case 8:  return "r14b"
                case 32: return "r14d"
                case 64: return "r14"
                case: unreachable()
            }
        case .R15:
            switch reg.bits {
                case 8:  return "r15b"
                case 32: return "r15d"
                case 64: return "r15"
                case: unreachable()
            }
        case: unreachable()
    }
}

print_inst :: proc(inst: Inst) {
    if .Lock in inst.flags {
        fmt.printf("lock ")
    }
    if .Rep in inst.flags {
        fmt.printf("rep ")
    }
    if .Repnz in inst.flags {
        fmt.printf("repnz ")
    }
    fmt.printf("%s", inst.opcode)
    for i in 0 ..< inst.operands_count {
        fmt.printf(i != 0? ", " : " ")
        operand := inst.operands[i]
        switch op in operand {
            case Mem_Operand:
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
                    sign := '+'
                    disp := op.disp
                    if op.disp < 0 {
                        sign = '-'
                        disp = -op.disp
                    }
                    fmt.printf("%c0x%02x", sign, disp)
                }
                fmt.printf("]")
            case Reg:
                fmt.printf("%s", reg_name(op))
            case Imm_Operand:
                fmt.printf("%08x", op.value)
        }
    }
    fmt.printf("\n")
}
