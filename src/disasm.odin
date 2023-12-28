package disasm

import "core:fmt"

Disasm_Ctx :: struct {
    bytes:      []u8,
    offset:     int,
    // CPU settings
    cpu_bits:   u8,
    // Instruction ctx
    inst_bits:  u8,
    // Bit reading
    last_byte:  u8,
    bits_offs:  u8,
}

read_u8 :: proc(ctx: ^Disasm_Ctx) -> (u8, bool) {
    assert(ctx.bits_offs == 0)
    if len(ctx.bytes) - ctx.offset >= 1 {
        b := ctx.bytes[ctx.offset]
        ctx.last_byte = ctx.bytes[ctx.offset]
        ctx.offset += 1
        return b, true
    }
    return 0, false
}

read_u16 :: proc(ctx: ^Disasm_Ctx) -> (u16, bool) {
    assert(ctx.bits_offs == 0)
    if len(ctx.bytes) - ctx.offset >= 2 {
        lo := cast(u16) ctx.bytes[ctx.offset+0]
        hi := cast(u16) ctx.bytes[ctx.offset+1]
        ctx.last_byte = ctx.bytes[ctx.offset+0]
        ctx.offset += 2
        return lo | (hi<<8), true
    }
    return 0, false
}

read_bits :: proc(ctx: ^Disasm_Ctx, count: u8) -> (bits: u8, ok: bool) {
    assert(count <= 8)
    if ctx.bits_offs == 0 {
        ctx.last_byte = read_u8(ctx) or_return
        ctx.bits_offs = 8
    }
    assert(ctx.bits_offs >= count)
    ctx.bits_offs -= count
    mask := cast(u8)(1<<count)-1
    bits = (ctx.last_byte >> ctx.bits_offs) & mask
    return bits, true
}

match_bits :: proc(ctx: ^Disasm_Ctx, bits: Tab_Bits) -> (matched: bool, ok: bool) {
    assert(bits.count <= 8)
    count := bits.count
    if ctx.bits_offs == 0 {
        ctx.last_byte = read_u8(ctx) or_return
        ctx.bits_offs = 8
    }
    offs := ctx.bits_offs - count
    mask := cast(u8)(1<<count) - 1
    found_bits := (ctx.last_byte >> offs) & mask
    matched = found_bits == bits.value
    if matched {
        assert(ctx.bits_offs >= count)
        ctx.bits_offs -= count
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
                    disp = cast(i32) read_u16(ctx) or_return
                } else if m == .Imm {
                    disp = cast(i32) read_u16(ctx) or_return
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
                    disp = cast(i32) read_u8(ctx) or_return
                } else if (mod == 0b00 && rm == 0b110) || mod == 0b10 {
                    disp = cast(i32) read_u16(ctx) or_return
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
    // fmt.printf("%v %v %v", encoding.name, op1, op2)
    fmt.printf("%v ", inst.opcode)
    for i in 0 ..< inst.operands_count {
        fmt.printf("%v ", inst.operands[i])
    }
    fmt.printf("\n")
    return true, true
}

disasm_inst :: proc(ctx: ^Disasm_Ctx) -> (ok: bool) {
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
                fmt.printf("bad byte: %02x\n", ctx.last_byte)
            }
            break
        }
        ctx.inst_bits = ctx.cpu_bits
    }
}

