package x86_disasm

import "core:io"
import "core:fmt"

print_intel_rx_op :: proc(w: io.Writer, rx: RX_Op) -> (err: io.Error) {
    assert(rx.kind != .None, "Function must be called with rx operand present")
    switch rx.kind {
    case .None: panic("Unknown rx register kind")
    case .GPReg: io.write_string(w, gpreg_name(rx.size, rx.reg)) or_return
    case .SReg:  io.write_string(w, sreg_name(rx.size, rx.reg)) or_return
    }
    return nil
}

print_intel_rm_op :: proc(w: io.Writer, seg: u8, rm: RM_Op) -> (err: io.Error) {
    assert(rm.kind != nil, "Function must be called when rm operand present")
    switch rm.kind {
    case .None: unreachable()
    case .GPReg:
        io.write_string(w, gpreg_name(rm.size, rm.reg)) or_return
    case .Mem_Addr_8, .Mem_Addr_16, .Mem_Addr_32:
        reg_size := u8(2) if rm.kind == .Mem_Addr_16 else 4
        switch rm.size {
        case 1: io.write_string(w, "byte ")
        case 2: io.write_string(w, "word ")
        case 4: io.write_string(w, "dword ")
        case 8: io.write_string(w, "oword ")
        }
        if seg != REG_NONE {
            io.write_string(w, sreg_name(2, seg)) or_return
            io.write_byte(w, ':') or_return
        }
        io.write_byte(w, '[')
        np := 0
        if rm.base_reg != REG_NONE {
            io.write_string(w, gpreg_name(reg_size, rm.base_reg)) or_return
            np += 1
        }
        if rm.index_reg != REG_NONE {
            if np > 0 {
                io.write_byte(w, '+') or_return
            }
            io.write_string(w, gpreg_name(reg_size, rm.index_reg)) or_return
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
            if rm.kind == .Mem_Addr_16 {
                fmt.wprintf(w, "%#.4x", i16(rm.disp))
            } else {
                fmt.wprintf(w, "%#.8x", rm.disp)
            }
            np += 1
        }
        io.write_byte(w, ']')
    }
    return nil
}

print_intel_eop :: proc(w: io.Writer, addr: u64, inst: Instruction) -> (err: io.Error) {
    eop := inst.extra_op
    assert(eop.kind != .None, "Function should be called when extra operand present")
    switch eop.kind {
    case .None: unreachable()
    case .Imm:
        switch eop.size {
        case 1: fmt.wprintf(w, "%#02x", eop.lo)
        case 2: fmt.wprintf(w, "%#04x", eop.lo)
        case 4: fmt.wprintf(w, "%#08x", eop.lo)
        case 8: fmt.wprintf(w, "%#016x", eop.lo)
        case: panic("Unkown extra operand size")
        }
    case .SAddr:
        fmt.wprintf(w, "%#02x", u8(eop.lo))
    case .NAddr:
        switch eop.size {
        case 2: fmt.wprintf(w, "%#04x", u16(addr+u64(inst.size)+eop.lo))
        case 4: fmt.wprintf(w, "%#08x", u32(addr+u64(inst.size)+eop.lo))
        case: panic("Unknown extra operand size")
        }
    case .FAddr:
        fmt.wprintf(w, "%#02x:", eop.hi)
        switch eop.size {
        case 2: fmt.wprintf(w, "%#04x", u16(eop.lo))
        case 4: fmt.wprintf(w, "%#08x", u32(eop.lo))
        case: panic("Unknown extra operand size")
        }
    }
    return nil
}

print_intel :: proc(w: io.Writer, addr: u64, inst: Instruction) -> (err: io.Error) {
    io.write_string(w, mnemonic_table[inst.mnemonic]) or_return
    if inst.flags >= {.Far} {
        io.write_string(w, " far") or_return
    }
    n := 0
    if .Direction_Bit not_in inst.flags {
        if inst.rm_op.kind != .None {
            io.write_byte(w, ' ') or_return
            print_intel_rm_op(w, inst.seg, inst.rm_op) or_return
            n += 1
        }
        if inst.rx_op.kind != .None {
            if n > 0 {
                io.write_byte(w, ',') or_return
            }
            io.write_byte(w, ' ') or_return
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
            }
            io.write_byte(w, ' ') or_return
            print_intel_rm_op(w, inst.seg, inst.rm_op) or_return
            n += 1
        }
    }
    if inst.extra_op.kind != nil {
        if n > 0 {
            io.write_byte(w, ',') or_return
        }
        io.write_byte(w, ' ') or_return
        print_intel_eop(w, addr, inst) or_return
        n += 1
    }
    return .None
}
