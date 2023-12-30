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
        add_operand(inst, Mem_Operand {
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
        scale = 1<<ss
        index = make_reg(rex_extend_i(ctx.rex, si), ctx.addr_bits)
    } else {
        base = make_reg(rex_extend_b(ctx.rex, rm), ctx.addr_bits)
    }
    if mod == 0b01 {
        disp = cast(i32) pop_u8(ctx) or_return
    } else if mod == 0b10 {
        disp = cast(i32) pop_u32(ctx) or_return
    }
    add_operand(inst, Mem_Operand {
        base = base,
        index = index,
        scale = scale,
        disp = disp,
    })
    return true
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
                    if ctx.data_bits == 16 {
                        imm  = cast(i64) pop_u16(ctx) or_return
                    } else if ctx.data_bits == 32 {
                        imm  = cast(i64) pop_u32(ctx) or_return
                    } else if ctx.data_bits == 64 {
                        imm  = cast(i64) pop_u64(ctx) or_return
                    }
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

    if has_fields[.Rx] {
        add_operand(&inst, make_reg(rex_extend_r(ctx.rex, fields[.Rx]), ctx.data_bits))
    }
    if has_fields[.Reg] {
        add_operand(&inst, make_reg(rex_extend_b(ctx.rex, fields[.Reg]), ctx.data_bits))
    }
    if has_fields[.Rega] {
        add_operand(&inst, make_reg(0, ctx.data_bits))
    }
    if has_fields[.Rm] {
        assert(has_fields[.Mod])
        mod := fields[.Mod]
        rm := fields[.Rm]
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
    if has_fields[.D] && fields[.D] == 0 {
        assert(inst.operands_count == 2)
        inst.operands[0], inst.operands[1] = inst.operands[1], inst.operands[0]
    }

    if has_fields[.Disp] {
        add_operand(&inst, make_mem(base = {}, index = {}, scale = 1, disp = disp))
    }
    if has_fields[.Imm] {
        add_operand(&inst, Imm_Operand {
            value = imm,
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
    for enc in decode_table {
        if match_bits(ctx, enc.opcode) or_continue {
            decode_inst(ctx, enc) or_return or_continue
            return true
        }
    }
    return false
}

disasm :: proc(bytes: []u8, default_bits := u8(64)) {
    ctx := Disasm_Ctx {
        bytes = bytes,
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
                case 16: return "si"
                case 32: return "esi"
                case 64: return "rsi"
                case: unreachable()
            }
        case .Bp:
            switch reg.bits {
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
                case 32: return "r9d"
                case 64: return "r9"
                case: unreachable()
            }
        case .R10:
            switch reg.bits {
                case 32: return "r10d"
                case 64: return "r10"
                case: unreachable()
            }
        case .R11:
            switch reg.bits {
                case 32: return "r11d"
                case 64: return "r11"
                case: unreachable()
            }
        case .R12:
            switch reg.bits {
                case 32: return "r12d"
                case 64: return "r12"
                case: unreachable()
            }
        case .R13:
            switch reg.bits {
                case 32: return "r13d"
                case 64: return "r13"
                case: unreachable()
            }
        case .R14:
            switch reg.bits {
                case 32: return "r14d"
                case 64: return "r14"
                case: unreachable()
            }
        case .R15:
            switch reg.bits {
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
