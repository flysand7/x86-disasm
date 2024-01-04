package disasm

import "core:fmt"
import "core:io"

COLOR_RESET :: "\e[0m"
COLOR_R :: "\e[38;5;210m"
COLOR_G :: "\e[38;5;114m"
COLOR_B :: "\e[38;5;105m"
COLOR_GREY :: "\e[38;5;242m"

@(private="file")
fmt_int :: proc(w: io.Writer, #any_int hex: i64) {
    sign_ch := '+'
    hex_abs := hex
    if hex < 0 {
        sign_ch = '-'
        hex_abs = -hex
    }
    if hex_abs < 10 {
        fmt.wprintf(w, "%c%d", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u8) {
        fmt.wprintf(w, "%c0x%02x", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u16) {
        fmt.wprintf(w, "%c0x%04x", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u32) {
        fmt.wprintf(w, "%c0x%08x", sign_ch, hex_abs)
    } else {
        fmt.wprintf(w, "%c0x%016x", sign_ch, hex_abs)
    }
}

print_inst :: proc(inst: Inst, w: io.Writer, colors := true) {
    WIDTH :: 15
    if colors {
        fmt.wprint(w, COLOR_GREY, sep="")
    }
    for i in 0 ..< len(inst.bytes) {
        fmt.wprintf(w, "%02x", inst.bytes[i])
    }
    if colors {
        fmt.wprint(w, COLOR_RESET, sep="")
    }
    for i in len(inst.bytes) ..< WIDTH {
        fmt.wprintf(w, "  ")
    }
    if colors {
        fmt.wprint(w, COLOR_R, sep="")
    }
    if .Lock in inst.flags {
        fmt.wprintf(w, "lock ")
    }
    if .Rep in inst.flags {
        fmt.wprintf(w, "rep ")
    }
    if .Repnz in inst.flags {
        fmt.wprintf(w, "repnz ")
    }
    fmt.wprintf(w, "%s", inst.mnemonic)
    if .Data_Size_Suffix in inst.flags {
        if inst.mnemonic == "c" {
            fmt.wprintf(w, "%s", data_size_suffix(inst.data_size/2))
        }
        fmt.wprintf(w, "%s", data_size_suffix(inst.data_size))
        if inst.mnemonic == "C" {
            fmt.wprintf(w, "%s", data_size_suffix(2*inst.data_size))
        }
    }
    if colors {
        fmt.wprint(w, COLOR_RESET, sep="")
    }
    for i in 0 ..< inst.op_count {
        fmt.wprintf(w, i != 0? ", " : " ")
        operand := inst.op[i]
        switch op in operand {
            case Mem_Short:
                fmt.wprintf(w, "short ")
                fmt_int(w, op.disp)
            case Mem:
                fmt.wprintf(w, "%s ", data_size_spec(inst.data_size))
                if inst.seg != nil {
                    fmt.wprintf(w, "%s:", sreg_name(inst.seg))
                }
                if selector, ok := inst.selector.?; ok {
                    fmt.wprintf(w, "%02x:", selector)
                }
                fmt.wprintf(w, "[")
                has_before := false
                if op.base.idx != nil {
                    print_color_string(w, COLOR_G, reg_name(op.base), colors)
                    has_before = true
                }
                if op.index.idx != nil {
                    fmt.wprintf(w, "%s%d*", has_before?"+":"", op.scale)
                    print_color_string(w, COLOR_G, reg_name(op.index), colors)
                }
                if op.disp != 0 {
                    fmt_int(w, op.disp)
                }
                fmt.wprintf(w, "]")
            case Reg:      print_color_string(w, COLOR_G, reg_name(op), colors)
            case MMX_Reg:  print_color_string(w, COLOR_G, mmxreg_name(op), colors)
            case XMM_Reg:  print_color_string(w, COLOR_G, xmmreg_name(op), colors)
            case Sreg:     print_color_string(w, COLOR_G, sreg_name(op), colors)
            case Creg_Idx: print_color_string(w, COLOR_G, creg_name(op), colors)
            case Dreg_Idx: print_color_string(w, COLOR_G, dreg_name(op), colors)
            case Imm:      print_color_int(w, COLOR_B, op.value, colors)
                
        }
    }
    fmt.wprintf(w, "\n")
}

print_color_string :: proc(w: io.Writer, color: string, str: string, colors: bool) {
    if colors {
        fmt.wprint(w, color, sep="")
    }
    fmt.wprintf(w, "%s", str)
    if colors {
        fmt.wprint(w, COLOR_RESET, sep="")
    }
}

print_color_int :: proc(w: io.Writer, color: string, str: i64, colors: bool) {
    if colors {
        fmt.wprint(w, color, sep="")
    }
    fmt_int(w, str)
    if colors {
        fmt.wprint(w, COLOR_RESET, sep="")
    }
}

data_size_suffix :: proc(size: u8) -> string {
    switch size {
        case 1:  return "b"
        case 2:  return "w"
        case 4:  return "d"
        case 8:  return "q"
        case 16: return "o"
        case 32: return "y"
        case: unreachable()
    }
}

data_size_spec :: proc(size: u8) -> string {
    switch size {
        case 1:  return "byte"
        case 2:  return "word"
        case 4:  return "dword"
        case 8:  return "qword"
        case 16: return "xmmword"
        case 32: return "ymmword"
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
                case 1: return "al"
                case 2: return "ax"
                case 4: return "eax"
                case 8: return "rax"
                case: unreachable()
            }
        case .Cx:
            switch reg.bits {
                case 1: return "cl"
                case 2: return "cx"
                case 4: return "ecx"
                case 8: return "rcx"
                case: unreachable()
            }
        case .Dx:
            switch reg.bits {
                case 1: return "dl"
                case 2: return "dx"
                case 4: return "edx"
                case 8: return "rdx"
                case: unreachable()
            }
        case .Bx:
            switch reg.bits {
                case 1: return "bl"
                case 2: return "bx"
                case 4: return "ebx"
                case 8: return "rbx"
                case: unreachable()
            }
        case .Di:
            switch reg.bits {
                case 1: return "ah"
                case 2: return "di"
                case 4: return "edi"
                case 8: return "rdi"
                case: unreachable()
            }
        case .Si:
            switch reg.bits {
                case 1: return "ch"
                case 2: return "si"
                case 4: return "esi"
                case 8: return "rsi"
                case: unreachable()
            }
        case .Sp:
            switch reg.bits {
                case 1: return "dh"
                case 2: return "sp"
                case 4: return "esp"
                case 8: return "rsp"
                case: unreachable()
            }
        case .Bp:
            switch reg.bits {
                case 1: return "bh"
                case 2: return "bp"
                case 4: return "ebp"
                case 8: return "rbp"
                case: unreachable()
            }
        case .R8:
            switch reg.bits {
                case 1: return "r8b"
                case 2: return "r8w"
                case 4: return "r8d"
                case 8: return "r8"
                case: unreachable()
            }
        case .R9:
            switch reg.bits {
                case 1: return "r9b"
                case 2: return "r9w"
                case 4: return "r9d"
                case 8: return "r9"
                case: unreachable()
            }
        case .R10:
            switch reg.bits {
                case 1: return "r10b"
                case 2: return "r10w"
                case 4: return "r10d"
                case 8: return "r10"
                case: unreachable()
            }
        case .R11:
            switch reg.bits {
                case 1: return "r11b"
                case 2: return "r11w"
                case 4: return "r11d"
                case 8: return "r11"
                case: unreachable()
            }
        case .R12:
            switch reg.bits {
                case 1: return "r12b"
                case 2: return "r12w"
                case 4: return "r12d"
                case 8: return "r12"
                case: unreachable()
            }
        case .R13:
            switch reg.bits {
                case 1: return "r13b"
                case 2: return "r13w"
                case 4: return "r13d"
                case 8: return "r13"
                case: unreachable()
            }
        case .R14:
            switch reg.bits {
                case 1: return "r14b"
                case 2: return "r14w"
                case 4: return "r14d"
                case 8: return "r14"
                case: unreachable()
            }
        case .R15:
            switch reg.bits {
                case 1: return "r15b"
                case 2: return "r15w"
                case 4: return "r15d"
                case 8: return "r15"
                case: unreachable()
            }
        case .Ip:
            switch reg.bits {
                case 2: return "ip"
                case 4: return "eip"
                case 8: return "rip"
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
    switch xmmreg.idx {
        case .Xmm0:
            switch xmmreg.bits {
                case 16: return "xmm0"
                case 32: return "ymm0"
            }
        case .Xmm1:
            switch xmmreg.bits {
                case 16: return "xmm1"
                case 32: return "ymm1"
            }
        case .Xmm2:
            switch xmmreg.bits {
                case 16: return "xmm2"
                case 32: return "ymm2"
            }
        case .Xmm3:
            switch xmmreg.bits {
                case 16: return "xmm3"
                case 32: return "ymm3"
            }
        case .Xmm4:
            switch xmmreg.bits {
                case 16: return "xmm4"
                case 32: return "ymm4"
            }
        case .Xmm5:
            switch xmmreg.bits {
                case 16: return "xmm5"
                case 32: return "ymm5"
            }
        case .Xmm6:
            switch xmmreg.bits {
                case 16: return "xmm6"
                case 32: return "ymm6"
            }
        case .Xmm7:
            switch xmmreg.bits {
                case 16: return "xmm7"
                case 32: return "ymm7"
            }
        case .Xmm8:
            switch xmmreg.bits {
                case 16: return "xmm8"
                case 32: return "ymm8"
            }
        case .Xmm9:
            switch xmmreg.bits {
                case 16: return "xmm9"
                case 32: return "ymm9"
            }
        case .Xmm10:
            switch xmmreg.bits {
                case 16: return "xmm10"
                case 32: return "ymm10"
            }
        case .Xmm11:
            switch xmmreg.bits {
                case 16: return "xmm11"
                case 32: return "ymm11"
            }
        case .Xmm12:
            switch xmmreg.bits {
                case 16: return "xmm12"
                case 32: return "ymm12"
            }
        case .Xmm13:
            switch xmmreg.bits {
                case 16: return "xmm13"
                case 32: return "ymm13"
            }
        case .Xmm14:
            switch xmmreg.bits {
                case 16: return "xmm14"
                case 32: return "ymm14"
            }
        case .Xmm15:
            switch xmmreg.bits {
                case 16: return "xmm15"
                case 32: return "ymm15"
            }
    }
    unreachable()
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

