package disasm

import "core:fmt"

Disasm_Ctx :: struct {
    bytes: []u8,
    bits:  u8,
}

read_u8 :: proc(ctx: ^Disasm_Ctx) -> (u8, bool) {
    if len(ctx.bytes) >= 1 {
        b := ctx.bytes[0]
        ctx.bytes = ctx.bytes[1:]
        return b, true
    }
    return 0, false
}

read_u16 :: proc(ctx: ^Disasm_Ctx) -> (u16, bool) {
    if len(ctx.bytes) >= 2 {
        lo := cast(u16) ctx.bytes[0]
        hi := cast(u16) ctx.bytes[1]
        ctx.bytes = ctx.bytes[2:]
        return lo | (hi<<8), true
    }
    return 0, false
}

Reg_Idx :: enum u8 {
    None,
    Ax,
    Cx,
    Dx,
    Bx,
    Sp,
    Bp,
    Si,
    Di,
}

Reg :: struct {
    idx:  Reg_Idx,
    bits: u8,
}

Mem_Operand :: struct {
    base:  Reg,
    index: Reg,
    disp:  i32,
    scale: u8,
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

Operand :: union {
    Reg,
    Mem_Operand,
}

parse_modrm :: proc(ctx: ^Disasm_Ctx, modrm: u8) -> (op1: Operand, op2: Operand, ok: bool) {
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
    mod := modrm >> 6
    rx := (modrm >> 3) & 0x7
    rm := (modrm) & 0x7
    assert(ctx.bits == 16)
    if ctx.bits == 16 {
        pair := base_regs[rm]
        base := pair.base
        index := pair.index
        disp: i32 = 0
        if mod == 0b11 {
            return make_reg(rx, 16), make_reg(rm, ctx.bits), true
        } else if mod == 0b01 {
            disp = cast(i32) read_u8(ctx) or_return
        } else if (mod == 0b00 && rm == 0b110) || mod == 0b10 {
            disp = cast(i32) read_u16(ctx) or_return
            if mod == 0b00 && rm == 0b110 {
                index = {}
                base  = {}
            }
        }
        return make_reg(rx, 16), make_mem(base = base, index = index, disp = disp), true
    }
    return nil, nil, false
}

disasm_inst :: proc(ctx: ^Disasm_Ctx) -> (ok: bool) {
    opcode := read_u8(ctx) or_return
    switch opcode {
        case 0x89:
            modrm := read_u8(ctx) or_return
            op1, op2 := parse_modrm(ctx, modrm) or_return
            fmt.println("mov", op2, op1)
            return true
        case 0x8b:
            modrm := read_u8(ctx) or_return
            op1, op2 := parse_modrm(ctx, modrm) or_return
            fmt.println("mov", op1, op2)
            return true
        case 0xa1:
            fmt.println("mov", Reg{.Ax, ctx.bits}, Mem_Operand{disp = cast(i32) read_u16(ctx) or_return})
            return true
    }
    return false
}

disasm :: proc(bytes: []u8) {
    ctx := Disasm_Ctx {
        bytes = bytes,
        bits  = 16,
    }
    bytes := bytes
    for disasm_inst(&ctx) {
    }
}

