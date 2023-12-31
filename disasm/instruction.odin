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

XMM_Reg_Idx :: enum u8 {
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
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
    size: u8,
}

XMM_Reg :: struct {
    idx: XMM_Reg_Idx,
    size: u8,
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
    mnemonic:  string,
    bytes:     []u8,
    data_size: u8,
    seg:       Sreg,
    selector:  Maybe(u16),
    op:        [4]Operand,
    op_count:  int,
    flags:     Inst_Flags,
}

add_operand :: proc(inst: ^Inst, operand: Operand) {
    assert(inst.op_count != len(inst.op))
    inst.op[inst.op_count] = operand
    inst.op_count += 1
    if xmm, ok := operand.(XMM_Reg); ok {
        inst.data_size = xmm.size
    }
}
