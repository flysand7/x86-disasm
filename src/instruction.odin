package disasm

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

Sreg :: enum {
    None,
    Cs,
    Ss,
    Ds,
    Es,
    Fs,
    Gs,
}

Mem_Operand :: struct {
    base:  Reg,
    index: Reg,
    disp:  i32 `fmt:"x"`,
    scale: u8,
}

Operand :: union {
    Reg,
    Mem_Operand,
}

Inst :: struct {
    opcode:         string,
    seg_override:   Sreg,
    operands:       [4]Operand,
    operands_count: int,
}

add_operand :: proc(inst: ^Inst, operand: Operand) {
    assert(inst.operands_count != len(inst.operands))
    inst.operands[inst.operands_count] = operand
    inst.operands_count += 1
}
