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
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

Test :: enum u8 {
    O,
    No,
    B,
    Ae,
    Z,
    Nz,
    Be,
    A,
    S,
    Ns,
    P,
    Np,
    L,
    Ge,
    Le,
    G,
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

Reg :: struct {
    idx:  Reg_Idx,
    bits: u8,
}

Imm_Operand :: struct {
    value: i64,
}

Mem_Operand :: struct {
    base:  Reg,
    index: Reg,
    disp:  i32 `fmt:"x"`,
    scale: u8,
}

Mem_Short_Operand :: struct {
    disp: i8,
}

Operand :: union {
    Reg,
    Mem_Operand,
    Mem_Short_Operand,
    Imm_Operand,
}

Inst_Flags :: bit_set[enum{
    Rep,
    Repnz,
    Lock,
    Bnd,
}]

Inst :: struct {
    opcode:         string,
    seg_override:   Sreg,
    selector:       Maybe(u16),
    test:           Maybe(Test),
    operands:       [4]Operand,
    operands_count: int,
    flags:          Inst_Flags,
}

add_operand :: proc(inst: ^Inst, operand: Operand) {
    assert(inst.operands_count != len(inst.operands))
    inst.operands[inst.operands_count] = operand
    inst.operands_count += 1
}
