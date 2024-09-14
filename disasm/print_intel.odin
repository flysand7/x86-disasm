package x86_disasm

import "core:io"
import "core:fmt"

gpreg_name :: proc(size: u8, reg: u8) -> string {
    if size == 2 {
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
    } else {
        panic("Registers of this size are not supported")
    }
}

print_intel_rx_op :: proc(w: io.Writer, rx: RX_Op) -> (err: io.Error) {
    assert(rx.kind != .None, "Function must be called with rx operand present")
    if rx.kind == .GPReg {
        io.write_string(w, gpreg_name(rx.size, rx.reg)) or_return
    }
    return nil
}

print_intel_rm_op :: proc(w: io.Writer, rm: RM_Op) -> (err: io.Error) {
    assert(rm.kind != nil, "Function must be called when rm operand present")
    switch rm.kind {
    case .None: unreachable()
    case .GPReg:
        io.write_string(w, gpreg_name(rm.size, rm.reg)) or_return
    case .Mem_Addr16:
        io.write_byte(w, '[')
        np := 0
        if rm.base_reg != REG_NONE {
            io.write_string(w, gpreg_name(2, rm.base_reg)) or_return
            np += 1
        }
        if rm.index_reg != REG_NONE {
            if np > 0 {
                io.write_byte(w, '+') or_return
            }
            io.write_string(w, gpreg_name(2, rm.index_reg)) or_return
            np += 1
        }
        if rm.scale != 1 {
            assert(rm.index_reg != REG_NONE)
            io.write_byte(w, '*') or_return
            io.write_int(w, int(rm.scale)) or_return
        }
        if np == 0 || rm.disp != 0 {
            if np > 0 && rm.disp >= 0 {
                io.write_byte(w, '+') or_return
            }
            fmt.wprintf(w, "%#.4x", i16(rm.disp))
            np += 1
        }
        io.write_byte(w, ']')
    }
    return nil
}

print_intel_eop :: proc(w: io.Writer, eop: EOP) -> (err: io.Error) {
    assert(eop.kind != .None, "Function should be called when extra operand present")
    switch eop.kind {
    case .None: unreachable()
    case .Imm:
        switch eop.size {
        case 1: fmt.wprintf(w, "%#.4x", eop.lo)
        case 2: fmt.wprintf(w, "%#.4x", eop.lo)
        case 4: fmt.wprintf(w, "%#.4x", eop.lo)
        case 8: fmt.wprintf(w, "%#.4x", eop.lo)
        case: panic("Unkown extra operand size")
        }
    }
    return nil
}

print_intel :: proc(w: io.Writer, inst: Instruction) -> (err: io.Error) {
    io.write_string(w, mnemonic_names[inst.mnemonic]) or_return
    n := 0
    if inst.flags >= {.Direction_Bit} {
        if inst.rm_op.kind != .None {
            io.write_byte(w, ' ') or_return
            print_intel_rm_op(w, inst.rm_op) or_return
            n += 1
        }
        if inst.rx_op.kind != .None {
            if n > 0 {
                io.write_byte(w, ',') or_return
                io.write_byte(w, ' ') or_return
            }
            print_intel_rx_op(w, inst.rx_op) or_return
            n += 1
        }
    } else {
        if inst.rx_op.kind != .None {
            io.write_byte(w, ' ') or_return
            print_intel_rx_op(w, inst.rx_op) or_return
            n += 1
        }
        if inst.rm_op.kind != .None {
            if n > 0 {
                io.write_byte(w, ',') or_return
                io.write_byte(w, ' ') or_return
            }
            print_intel_rm_op(w, inst.rm_op) or_return
            n += 1
        }
    }
    if inst.extra_op.kind != nil {
        if n > 0 {
            io.write_byte(w, ',') or_return
            io.write_byte(w, ' ') or_return
        }
        print_intel_eop(w, inst.extra_op) or_return
        n += 1
    }
    return .None
}
