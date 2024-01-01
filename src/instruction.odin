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
    Ip,
}

MMX_Reg :: enum u8 {
    Mm0,
    Mm1,
    Mm2,
    Mm3,
    Mm4,
    Mm5,
    Mm6,
    Mm7,
}

XMM_Reg :: enum u8 {
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
}

Creg_Idx :: enum u8 {
    Cr0,
    Cr1,
    Cr2,
    Cr3,
    Cr4,
    Cr5,
    Cr6,
    Cr7,
}

Dreg_Idx :: enum u8 {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
    Dr4,
    Dr5,
    Dr6,
    Dr7,
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
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

Reg :: struct {
    idx:  Reg_Idx,
    bits: u8,
}

Imm :: struct {
    value: i64,
}

Mem :: struct {
    base:  Reg,
    index: Reg,
    disp:  i32 `fmt:"x"`,
    scale: u8,
}

Mem_Short :: struct {
    disp: i8,
}

Operand :: union {
    Reg,
    MMX_Reg,
    XMM_Reg,
    Mem,
    Mem_Short,
    Imm,
    Creg_Idx,
    Dreg_Idx,
    Sreg,
}

Inst_Flags :: bit_set[enum{
    Rep,
    Repnz,
    Lock,
    Bnd,
    Data_Size_Suffix,
}]

Inst :: struct {
    opcode:         string,
    bytes:          []u8,
    data_size:      u8,
    seg_override:   Sreg,
    selector:       Maybe(u16),
    operands:       [4]Operand,
    operands_count: int,
    flags:          Inst_Flags,
}

add_operand :: proc(inst: ^Inst, operand: Operand) {
    assert(inst.operands_count != len(inst.operands))
    inst.operands[inst.operands_count] = operand
    inst.operands_count += 1
}
