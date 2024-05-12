package x86_disasm

CPU_Mode :: enum {
    Mode_16,
    Mode_32,
    Mode_64,
}

// TODO: will probably get generated from a table.
Mnemonic :: enum {

}

Instruction_Flag :: enum {
    // Swaps around RX and RM operands.
    // If not present, RM follows RX (intel syntax).
    // If present, RX is follows RM (intel syntax).
    // For AT&T syntax the ordering is reversed. 
    Direction_Bit,
}

RX_Operand :: struct {
    kind: u8,
    size_log2: u8,
    register: u8,
}

RM_Operand :: struct {
    kind: u8,
    size_log2: u8,
    using _: struct #raw_union {
        register: u8,
        base_reg: u8,
    },
    index_reg: u8,
    scale: u8,
    disp: i32,
}

VEX_Operand :: struct {
    kind: u8,
    size_log2: u8,
    register: u8,
}

Extra_Operand_Kind :: enum {}

// At most a 16-byte value packed into two integers.
// Value1 contains the least-significant eight bytes.
// Value2 contains the most-significant eight bytes.
Extra_Operand :: struct {
    kind: Extra_Operand_Kind,
    size_log2: u8,
    value1: u64,
    value2: u64,
}

Instruction :: struct {
    mnemonic: Mnemonic,
    flags: bit_set[Instruction_Flag],
    rx_op: RX_Operand,
    rm_op: RM_Operand,
    vex_op: VEX_Operand,
    extra_op: Extra_Operand,
}

cpu_mode := CPU_Mode.Mode_16

set_cpu_mode :: proc(mode: CPU_Mode) {
    cpu_mode = mode
}

disasm_all :: proc(bytes: []u8) -> [dynamic]Instruction {
    insts := make([dynamic]Instruction)
    bytes := bytes
    for instruction, len in disasm_one(bytes) {
        append(&insts, instruction)
        bytes := bytes[len:]
    }
    return insts
}

disasm_one :: proc(bytes: []u8) -> (Instruction, int, bool) {
    return {}, 0, false
}


