package disasm

import "core:fmt"

Disasm_Ctx :: struct {
    bytes:      []u8,
    offset:     int,
    // CPU settings
    cpu_bits:   u8,
    // Instruction ctx
    inst_bits:  u8,
    seg_override: Sreg,
    // Bit reading
    bits_offs:  u8,
}

pop_u8 :: proc(ctx: ^Disasm_Ctx) -> (u8, bool) {
    assert(ctx.bits_offs % 8 == 0)
    if len(ctx.bytes) - ctx.offset >= 1 {
        b := ctx.bytes[ctx.offset]
        ctx.offset += 1
        ctx.bits_offs = 8
        return b, true
    }
    return 0, false
}

peek_u8 :: proc(ctx: ^Disasm_Ctx) -> (u8, bool) {
    assert(ctx.bits_offs % 8 == 0)
    if ctx.offset >= len(ctx.bytes) {
        return 0, false
    }
    return ctx.bytes[ctx.offset], true
}

match_u8 :: proc(ctx: ^Disasm_Ctx, b: u8) -> (bool) {
    assert(ctx.offset < len(ctx.bytes))
    if ctx.bytes[ctx.offset] == b {
        ctx.offset += 1
        return true
    }
    return false
}

pop_u16 :: proc(ctx: ^Disasm_Ctx) -> (u16, bool) {
    assert(ctx.bits_offs % 8 == 0)
    if len(ctx.bytes) - ctx.offset >= 2 {
        lo := ctx.bytes[ctx.offset+0]
        hi := ctx.bytes[ctx.offset+1]
        ctx.bits_offs = 8
        ctx.offset += 2
        return u16(lo) | (u16(hi)<<8), true
    }
    return 0, false
}

read_bits :: proc(ctx: ^Disasm_Ctx, count: u8) -> (bits: u8, ok: bool) {
    assert(count <= 8)
    assert(ctx.bits_offs >= count)
    assert(ctx.offset < len(ctx.bytes))
    ctx.bits_offs -= count
    mask := cast(u8)(1<<count)-1
    bits = (ctx.bytes[ctx.offset] >> ctx.bits_offs) & mask
    if ctx.bits_offs == 0 {
        ctx.offset += 1
        ctx.bits_offs = 8
    }
    return bits, true
}

match_bits :: proc(ctx: ^Disasm_Ctx, bits: Tab_Bits) -> (matched: bool, ok: bool) {
    assert(bits.count <= 8)
    assert(ctx.bits_offs >= bits.count)
    count := bits.count
    offs := ctx.bits_offs - count
    mask := cast(u8)(1<<count) - 1
    found_bits := (ctx.bytes[ctx.offset] >> offs) & mask
    matched = found_bits == bits.value
    if matched {
        assert(ctx.bits_offs >= count)
        ctx.bits_offs -= count
    }
    if ctx.bits_offs == 0 {
        ctx.offset += 1
        ctx.bits_offs = 8
    }
    return matched, true
}

make_reg :: proc(idx: u8, bits: u8) -> Reg {
    return {
        idx  = cast(Reg_Idx) (idx + 1),
        bits = bits,
    }
}

make_mem :: proc(base: Reg, index: Reg = {}, scale := u8(1), disp := i32(0)) -> Mem_Operand {
    return {
        base  = base,
        index = index,
        scale = scale,
        disp  = disp,
    }
}

make_sreg :: proc(idx: u8) -> Sreg {
    return cast(Sreg) (idx + 1)
}

parse_modrm :: proc(ctx: ^Disasm_Ctx, modrm: u8) -> (op1: Operand, op2: Operand, ok: bool) {
    mod := modrm >> 6
    rx := (modrm >> 3) & 0x7
    rm := (modrm) & 0x7
    assert(ctx.inst_bits == 16)
    return nil, nil, false
}

decode_inst :: proc(ctx: ^Disasm_Ctx, encoding: Tab_Inst) -> (matched: bool, ok: bool) {
    fields: [Tab_Field]u8
    has_fields: [Tab_Field]bool
    disp: i32 = 0
    imm:  i64 = 0
    for mask in encoding.masks {
        switch m in mask {
        case Tab_Bits:
            if !(match_bits(ctx, m) or_return) {
                return false, true
            }
        case Tab_Field:
            field_size := field_widths[m]
            assert(!has_fields[m])
            has_fields[m] = true
            if field_size == 0 {
                if m == .Disp {
                    disp = cast(i32) pop_u16(ctx) or_return
                } else if m == .Imm {
                    disp = cast(i32) pop_u16(ctx) or_return
                } else if m == .Rega {
                    // No associated data
                } else {
                    panic("Unhandled zero-sized field")
                }
            } else {
                fields[m] = read_bits(ctx, field_size) or_return
            }
        }
    }
    inst := Inst {
        opcode = encoding.name,
        seg_override = ctx.seg_override,
    }
    if has_fields[.Rx] {
        add_operand(&inst, make_reg(fields[.Rx], ctx.inst_bits))
    }
    if has_fields[.Rega] {
        add_operand(&inst, make_reg(0, ctx.inst_bits))
    }
    if has_fields[.Rm] {
        assert(has_fields[.Mod])
        mod := fields[.Mod]
        rm := fields[.Rm]
        if ctx.inst_bits == 16 {
            base_regs: [8]struct{base: Reg, index: Reg} = {
                {base = {.Bx, 16}, index = {.Si,  16}},
                {base = {.Bx, 16}, index = {.Di,  16}},
                {base = {.Bp, 16}, index = {.Si,  16}},
                {base = {.Bp, 16}, index = {.Di,  16}},
                {base = {.Si, 16}, index = {.None, 0}},
                {base = {.Di, 16}, index = {.None, 0}},
                {base = {.Bp, 16}, index = {.None, 0}},
                {base = {.Bx, 16}, index = {.None, 0}},
            }
            pair := base_regs[rm]
            base := pair.base
            index := pair.index
            disp: i32 = 0
            if mod == 0b11 {
                add_operand(&inst, make_reg(rm, ctx.inst_bits))
            } else {
                if mod == 0b01 {
                    disp = cast(i32) pop_u8(ctx) or_return
                } else if (mod == 0b00 && rm == 0b110) || mod == 0b10 {
                    disp = cast(i32) pop_u16(ctx) or_return
                    if mod == 0b00 && rm == 0b110 {
                        index = {}
                        base  = {}
                    }
                }
                add_operand(&inst, make_mem(base = base, index = index, disp = disp))
            }
        } else {
            panic("Unhandled instruction bits")
        }
    } else if has_fields[.Disp] {
        add_operand(&inst, make_mem(base = {}, index = {}, scale = 1, disp = disp))
    }
    print_inst(inst)
    return true, true
}

disasm_inst :: proc(ctx: ^Disasm_Ctx) -> (ok: bool) {
    switch peek_u8(ctx) or_return {
        case 0x2e: ctx.seg_override = .Cs
        case 0x36: ctx.seg_override = .Ss
        case 0x3e: ctx.seg_override = .Ds
        case 0x26: ctx.seg_override = .Es
        case 0x64: ctx.seg_override = .Fs
        case 0x65: ctx.seg_override = .Gs
    }
    if ctx.seg_override != nil {
        pop_u8(ctx) or_return
    }
    for enc in decode_table {
        if match_bits(ctx, enc.opcode) or_continue {
            decode_inst(ctx, enc) or_return or_continue
            return true
        }
    }
    return false
}

disasm :: proc(bytes: []u8) {
    ctx := Disasm_Ctx {
        bytes = bytes,
        cpu_bits  = 16,
        inst_bits = 16,
    }
    for {
        if !disasm_inst(&ctx) {
            if len(ctx.bytes) - ctx.offset > 0 {
                fmt.printf("bad byte: %02x\n", peek_u8(&ctx))
            }
            break
        }
        ctx.inst_bits = ctx.cpu_bits
        ctx.seg_override = nil
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
                case 16: return "ax"
                case 32: return "eax"
                case 64: return "rax"
                case: unreachable()
            }
        case .Cx:
            switch reg.bits {
                case 16: return "cx"
                case 32: return "ecx"
                case 64: return "rcx"
                case: unreachable()
            }
        case .Bx:
            switch reg.bits {
                case 16: return "bx"
                case 32: return "ebx"
                case 64: return "rbx"
                case: unreachable()
            }
        case .Dx:
            switch reg.bits {
                case 16: return "dx"
                case 32: return "edx"
                case 64: return "rdx"
                case: unreachable()
            }
        case .Di:
            switch reg.bits {
                case 16: return "di"
                case 32: return "edi"
                case 64: return "rdi"
                case: unreachable()
            }
        case .Si:
            switch reg.bits {
                case 16: return "sp"
                case 32: return "esp"
                case 64: return "rsp"
                case: unreachable()
            }
        case .Sp:
            switch reg.bits {
                case 16: return "sp"
                case 32: return "esp"
                case 64: return "rsp"
                case: unreachable()
            }
        case .Bp:
            switch reg.bits {
                case 16: return "bp"
                case 32: return "ebp"
                case 64: return "rbp"
                case: unreachable()
            }
        case: unreachable()
    }
}

print_inst :: proc(inst: Inst) {
    fmt.printf("%s", inst.opcode)
    for i in 0 ..< inst.operands_count {
        fmt.printf(i != 0? ", " : " ")
        operand := inst.operands[i]
        switch op in operand {
            case Mem_Operand:
                if inst.seg_override != nil {
                    fmt.printf("%s:", sreg_name(inst.seg_override))
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
                    fmt.printf("%04x", op.disp)
                }
                fmt.printf("]")
            case Reg:
                fmt.printf("%s", reg_name(op))
        }
    }
    fmt.printf("\n")
}
