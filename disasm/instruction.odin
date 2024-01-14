package disasm

import "table"

Size :: table.Size
Reg_Set :: table.Reg_Set

Reg :: struct {
    kind: Reg_Set,
    size: Size,
    idx:  u8,
}

reg_present :: proc(r: Reg) -> bool {
    return r.size != .Default
}

Imm :: struct {
    value: i64,
}

Mem :: struct {
    size:  Size,
    base:  Reg,
    index: Reg,
    disp:  i32 `fmt:"x"`,
    scale: u8,
}

Mem_Short :: struct {
    disp: i8,
}

Mem_Near :: struct {
    size: Size,
    offs: i32,
}

Mem_Far :: struct {
    size: Size,
    seg:  u16,
    offs: i32,
}

Operand :: union {
    Reg,
    Mem,
    Mem_Short,
    Mem_Near,
    Mem_Far,
    Imm,
}

Inst_Flags :: bit_set[enum{
    Rep,
    Repz,
    Repnz,
    Lock,
    Bnd,
}]

Inst :: struct {
    mnemonic:  string,
    length:    int,
    seg:       Reg,
    op:        [4]Operand,
    op_count:  int,
    flags:     Inst_Flags,
}

add_operand :: proc(inst: ^Inst, operand: Operand) {
    assert(inst.op_count != len(inst.op))
    inst.op[inst.op_count] = operand
    inst.op_count += 1
}
