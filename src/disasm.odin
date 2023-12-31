package disasm

import "core:fmt"

Disasm_Ctx :: struct {
    bytes:      []u8,
    offset:     int,
    // CPU settings
    cpu_bits:   u8,
    // Instruction ctx
    rex:        u8,
    data_bits:  u8,
    addr_bits:  u8,
    seg_override: Sreg,
    lock:       bool,
    repnz:      bool,
    rep_or_bnd: bool,
    // Bit reading
    bits_offs:  u8,
}

Inst_Fields :: struct {
    bits: [Tab_Field]u8,
    has:  [Tab_Field]bool,
    disp:  i32,
    disp8: i8,
    imm:   i64,
    sel:   u16,
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
        v := cast(u16) (cast(^u16le) &ctx.bytes[ctx.offset])^
        ctx.bits_offs = 8
        ctx.offset += 2
        return v, true
    }
    return 0, false
}

pop_u32 :: proc(ctx: ^Disasm_Ctx) -> (u32, bool) {
    assert(ctx.bits_offs % 8 == 0)
    if len(ctx.bytes) - ctx.offset >= 4 {
        v := cast(u32) (cast(^u32le) &ctx.bytes[ctx.offset])^
        ctx.bits_offs = 8
        ctx.offset += 4
        return v, true
    }
    return 0, false
}

pop_u64 :: proc(ctx: ^Disasm_Ctx) -> (u64, bool) {
    assert(ctx.bits_offs % 8 == 0)
    if len(ctx.bytes) - ctx.offset >= 8 {
        v := cast(u64) (cast(^u64le) &ctx.bytes[ctx.offset])^
        ctx.bits_offs = 8
        ctx.offset += 8
        return v, true
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

make_mem :: proc(base: Reg, index: Reg = {}, scale := u8(1), disp := i32(0)) -> Mem {
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

rex_extend_b :: #force_inline proc(rex: u8, value: u8) -> u8 {
    return (rex & 0b0001) << 3 | value
}

rex_extend_i :: #force_inline proc(rex: u8, value: u8) -> u8 {
    return (rex & 0b0010) << 2 | value
}

rex_extend_r :: #force_inline proc(rex: u8, value: u8) -> u8 {
    return (rex & 0b0100) << 1 | value
}

parse_modrm :: proc(ctx: ^Disasm_Ctx, modrm: u8) -> (op1: Operand, op2: Operand, ok: bool) {
    mod := modrm >> 6
    rx := (modrm >> 3) & 0x7
    rm := (modrm) & 0x7
    assert(ctx.data_bits == 16)
    return nil, nil, false
}

add_modrm_addr16 :: proc(ctx: ^Disasm_Ctx, inst: ^Inst, mod: u8, rm: u8) -> (ok: bool) {
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
    disp := i32(0)
    if mod == 0b11 {
        add_operand(inst, make_reg(rm, 16))
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
        add_operand(inst, make_mem(base = base, index = index, disp = disp))
    }
    return true
}

add_modrm_addr32 :: proc(ctx: ^Disasm_Ctx, inst: ^Inst, mod: u8, rm: u8) -> (ok: bool) {
    if mod == 0b00 && rm == 0b101 {
        add_operand(inst, Mem {
            disp = cast(i32) pop_u32(ctx) or_return,
        })
        return true
    }
    if mod == 0b11 {
        add_operand(inst, make_reg(rex_extend_b(ctx.rex, rm), ctx.data_bits))
        return true
    }
    disp := i32(0)
    base := Reg {}
    index := Reg {}
    scale := u8(0)
    if rm == 0b100 {
        sib := pop_u8(ctx) or_return
        ss := sib >> 6
        si := (sib >> 3) & 0x7
        sb := sib & 0x7
        if sb == 0b101 && (mod == 0b01 || mod == 0b10) {
            base = {
                idx = .Bp,
                bits = ctx.addr_bits,
            }
        } else {
            base = make_reg(rex_extend_b(ctx.rex, sb), ctx.addr_bits)
        }
        if si != 0b100 {
            scale = 1<<ss
            index = make_reg(rex_extend_i(ctx.rex, si), ctx.addr_bits)
        }
    } else {
        base = make_reg(rex_extend_b(ctx.rex, rm), ctx.addr_bits)
    }
    if mod == 0b01 {
        disp = cast(i32) pop_u8(ctx) or_return
    } else if mod == 0b10 {
        disp = cast(i32) pop_u32(ctx) or_return
    }
    add_operand(inst, Mem {
        base = base,
        index = index,
        scale = scale,
        disp = disp,
    })
    return true
}

read_field :: proc(ctx: ^Disasm_Ctx, fields: ^Inst_Fields, field: Tab_Field) -> (matched, ok: bool) {
    field_size := field_widths[field]
    assert(!fields.has[field])
    fields.has[field] = true
    if field_size != 0 {
        bits := read_bits(ctx, field_size) or_return
        if field == .Moda {
            fields.bits[.Mod] = bits
            fields.has[.Mod]  = true
            if bits == 0b11 {
                return false, true
            }
        } else if field == .Modb {
            fields.bits[.Mod] = bits
            fields.has[.Mod]  = true
            if bits == 0b10 || bits == 0b01 {
                return false, true
            }
        } else if field == .Modab {
            fields.bits[.Mod] = bits
            fields.has[.Mod]  = true
            if bits != 0b00 {
                return false, true
            }
        } else {
            fields.bits[field] = bits
        }
        return true, true
    }
    #partial switch field {
        case .Disp:
            fields.disp = cast(i32) pop_u16(ctx) or_return
        case .Disp8:
            fields.disp8 = cast(i8) pop_u8(ctx) or_return
        case .Imm:
            if fields.has[.S] && fields.bits[.S] != 0 && fields.has[.W] && fields.bits[.W] != 0 {
                fields.imm = cast(i64) pop_u8(ctx) or_return
            } else if ctx.data_bits == 16 {
                fields.imm = cast(i64) pop_u16(ctx) or_return
            } else if ctx.data_bits == 32 {
                fields.imm = cast(i64) pop_u32(ctx) or_return
            } else if ctx.data_bits == 64 {
                fields.imm = cast(i64) pop_u64(ctx) or_return
            }
        case .Imm8:
            fields.imm = cast(i64) pop_u8(ctx) or_return
        case .Imm16:
            fields.imm = cast(i64) pop_u16(ctx) or_return
        case .Sel:
            fields.sel = pop_u16(ctx) or_return
        case ._1:
        case ._c:
        case ._a:
            // No associated data
        case ._d:
            fields.has[.D] = true
            fields.bits[.D] = 0
        case ._64:
            ctx.data_bits = 64
        case:
            panic("Unhandled zero-length field")
    }
    return true, true
}

match_field :: proc(ctx: ^Disasm_Ctx, fields: ^Inst_Fields, mask: Tab_Mask) -> (matched, ok: bool) {
    switch m in mask {
        case Tab_Bits:
            return match_bits(ctx, m)
        case Ign_Bits:
            _, ok := read_bits(ctx, m.count)
            return true, ok
        case Tab_Field:
            return read_field(ctx, fields, m)
    }
    return true, true
}

decode_inst :: proc(ctx: ^Disasm_Ctx, encoding: Tab_Inst) -> (matched: bool, ok: bool) {
    fields := Inst_Fields {}
    for mask in encoding.masks {
        matched := match_field(ctx, &fields, mask) or_return
        if !matched {
            return false, true
        }
    }
    inst := Inst {
        opcode = encoding.name,
        seg_override = ctx.seg_override,
    }
    if ctx.lock {
        inst.flags |= {.Lock}
    }
    if ctx.repnz {
        inst.flags |= {.Repnz}
    }
    if ctx.rep_or_bnd {
        switch inst.opcode {
            case "call": fallthrough
            case "ret":  fallthrough
            case "jmp":  inst.flags |= {.Bnd}
            case: inst.flags |= {.Rep}
        }
    }
    if fields.has[.W] {
        if fields.bits[.W] == 0 {
            ctx.data_bits = 8
        }
    }
    if fields.has[.Tttn] {
        inst.test = cast(Test) fields.bits[.Tttn]
    }

    if fields.has[.Rx] {
        add_operand(&inst, make_reg(
            rex_extend_r(ctx.rex, fields.bits[.Rx]),
            ctx.data_bits,
        ))
    } else if fields.has[.Eee] {
        assert(fields.bits[.Eee] < cast(u8) max(Creg_Idx))
        add_operand(&inst, cast(Creg_Idx) fields.bits[.Eee])
    } else if fields.has[.Ddd] {
        assert(fields.bits[.Eee] < cast(u8) max(Dreg_Idx))
        add_operand(&inst, cast(Dreg_Idx) fields.bits[.Ddd])
    } else if fields.has[.Sr2] {
        assert(fields.bits[.Sr2] < cast(u8) max(Sreg))
        add_operand(&inst, make_sreg(fields.bits[.Sr2]))
    } else if fields.has[.Sr3] {
        assert(fields.bits[.Sr3] < cast(u8) max(Sreg))
        add_operand(&inst, make_sreg(fields.bits[.Sr3]))
    } else if fields.has[._c] {
        add_operand(&inst, Reg{.Cx, 8})
    }
    if fields.has[.Reg] {
        add_operand(&inst, make_reg(
            rex_extend_b(ctx.rex, fields.bits[.Reg]),
            ctx.data_bits,
        ))
    }
    if fields.has[._a] {
        add_operand(&inst, make_reg(0, ctx.data_bits))
    }
    if fields.has[.Sel] {
        inst.selector = fields.sel
    }
    if fields.has[.Rm] {
        assert(fields.has[.Mod])
        mod := fields.bits[.Mod]
        rm := fields.bits[.Rm]
        if ctx.addr_bits == 16 {
            add_modrm_addr16(ctx, &inst, mod, rm)
        } else if ctx.addr_bits == 32 || ctx.addr_bits == 64 {
            add_modrm_addr32(ctx, &inst, mod, rm)
        } else {
            panic("Bad addr bits")
        }
    }

    /*
        At this point we only have reg / rm fields
        So we can just swap the operands if d bit is reset.
    */
    if fields.has[.D] && fields.bits[.D] == 0 {
        assert(inst.operands_count == 2)
        inst.operands[0], inst.operands[1] = inst.operands[1], inst.operands[0]
    }

    if fields.has[.Disp] {
        add_operand(&inst, make_mem(base = {}, index = {}, scale = 1, disp = fields.disp))
    } else if fields.has[.Disp8] {
        add_operand(&inst, Mem_Short { disp = fields.disp8 })
    }
    if fields.has[.Imm] {
        add_operand(&inst, Imm {
            value = fields.imm,
        })
    } else if fields.has[._1] {
        add_operand(&inst, Imm {
            value = 1,
        })
    }

    print_inst(inst)
    return true, true
}

disasm_inst :: proc(ctx: ^Disasm_Ctx) -> (ok: bool) {
    Prefix_Group :: bit_set[enum{
        Gr1,
        Gr2,
        Gr3,
        Gr4,
    }]
    groups := Prefix_Group {}
    addr_size_override := false
    data_size_override := false
    for !(groups == ~{}) {
        delta  := Prefix_Group {}
        if .Gr1 not_in groups {
            delta += {.Gr1}
            switch peek_u8(ctx) or_return {
                case 0xf0: ctx.lock = true
                case 0xf2: ctx.repnz = true
                case 0xf3: ctx.rep_or_bnd = true
                case: delta -= {.Gr1}
            }
        }
        if .Gr2 not_in groups {
            switch peek_u8(ctx) or_return {
                case 0x2e: ctx.seg_override = .Cs
                case 0x36: ctx.seg_override = .Ss
                case 0x3e: ctx.seg_override = .Ds
                case 0x26: ctx.seg_override = .Es
                case 0x64: ctx.seg_override = .Fs
                case 0x65: ctx.seg_override = .Gs
            }
            if ctx.seg_override != nil {
                delta += {.Gr2}
            } else {
                switch peek_u8(ctx) or_return {
                    case 0x2e: fallthrough
                    case 0x3e: delta += {.Gr2}
                }
            }
        }
        if .Gr3 not_in groups {
            if (peek_u8(ctx) or_return) == 0x66 {
                delta += {.Gr3}
                data_size_override = true
            }
        }
        if .Gr4 not_in groups {
            if (peek_u8(ctx) or_return) == 0x67 {
                delta += {.Gr4}
                addr_size_override = true
            }
        }
        if delta != nil {
            pop_u8(ctx) or_return
            groups |= delta
        } else {
            break
        }
    }
    if (peek_u8(ctx) or_return) & 0xf0 == 0x40 {
        ctx.rex = pop_u8(ctx) or_return
    }
    if ctx.rex & 0b1000 == 0b1000 {
        if addr_size_override {
           ctx.addr_bits = 32
        }
        ctx.data_bits = 64
    } else {
        if data_size_override {
            if ctx.data_bits == 16 {
                ctx.data_bits = 32
            } else if ctx.data_bits == 32 {
                ctx.data_bits = 16
            }
        }
        if addr_size_override {
            if ctx.addr_bits == 16 || ctx.addr_bits == 64 {
                ctx.addr_bits = 32
            } else if ctx.addr_bits == 32 {
                ctx.addr_bits = 16
            }
        }
    }
    saved_offset := ctx.offset
    for enc in decode_table {
        if .N64 in enc.flags && ctx.cpu_bits == 64 {
            continue
        }
        ctx.offset    = saved_offset
        ctx.bits_offs = 8
        if match_bits(ctx, enc.opcode) or_continue {
            matched := decode_inst(ctx, enc) or_return
            if matched {
                return true
            }
        }
    }
    return false
}

disasm :: proc(bytes: []u8, default_bits := u8(64)) {
    ctx := Disasm_Ctx {
        bytes = bytes,
        bits_offs = 8,
        cpu_bits  = default_bits,
    }
    for {
        ctx.data_bits = ctx.cpu_bits == 64? 32 : ctx.cpu_bits
        ctx.addr_bits = ctx.cpu_bits
        ctx.seg_override = nil
        ctx.lock = false
        ctx.repnz = false
        ctx.rep_or_bnd = false
        ctx.rex = 0
        if !disasm_inst(&ctx) {
            if len(ctx.bytes) - ctx.offset > 0 {
                b, _ := peek_u8(&ctx)
                fmt.printf("bad byte: %02x\n", b)
            }
            break
        }
    }
}

