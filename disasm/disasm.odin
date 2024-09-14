package x86_disasm

CPU_Mode :: enum {
    Mode_16,
    Mode_32,
    Mode_64,
}

// TODO: will probably get generated from a table.
Mnemonic :: enum {
    Mov,
}

Instruction_Flag :: enum {
    // Swaps around RX and RM operands.
    // If not present, RM follows RX (intel syntax).
    // If present, RX is follows RM (intel syntax).
    // For AT&T syntax the ordering is reversed. 
    Direction_Bit,
}

RX_Op_Kind :: enum u8 {
    None,
    GPReg,
}

RX_Op :: struct {
    kind: RX_Op_Kind,
    size: u8,
    reg: u8,
}

rx_gpreg16 :: proc(reg: u8) -> RX_Op {
    return RX_Op {
        kind = .GPReg,
        size = 2,
        reg = reg,
    }
}

RM_Op_Kind :: enum u8 {
    None,
    Mem_Addr16,
    GPReg,
}

RM_Op :: struct {
    kind: RM_Op_Kind,
    size: u8,
    using _: struct #raw_union {
        reg: u8,
        base_reg: u8,
    },
    index_reg: u8,
    scale: u8,
    disp: i32,
}

rm_gpreg16 :: proc(reg: u8) -> RM_Op {
    return RM_Op {
        kind = .GPReg,
        size = 2,
        reg = reg,
    }
}

rm_mem16_addr16 :: proc(base_reg: u8, index_reg: u8, disp: i32) -> RM_Op {
    return RM_Op {
        kind = .Mem_Addr16,
        size = 2,
        base_reg = base_reg,
        index_reg = index_reg,
        scale = 1, // No scae in 16-bit addressing
        disp = disp,
    }
}

VEX_Op :: struct {
    kind: u8,
    size: u8,
    reg: u8,
}

EOP_Kind :: enum {
    None,
    Imm,
}

// At most a 16-byte value packed into two integers, so the values are split
// into two 64-bit integers, hi and lo.
EOP :: struct {
    kind: EOP_Kind,
    size: u8,
    lo: u64,
    hi: u64,
}

eop_imm16 :: proc(value: u16le) -> EOP {
    return EOP {
        kind = .Imm,
        size = 2,
        lo = u64(value),
        hi = 0,
    }
}

Instruction :: struct {
    mnemonic: Mnemonic,
    flags: bit_set[Instruction_Flag],
    rx_op: RX_Op,
    rm_op: RM_Op,
    vex_op: VEX_Op,
    extra_op: EOP,
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
        bytes = bytes[len:]
    }
    return insts
}

import "core:fmt"

disasm_one :: proc(bytes: []u8) -> (Instruction, int, bool) {
    if len(bytes) == 0 {
        return {}, 0, false
    }
    idx := 0
    opcode := bytes[idx]
    idx += 1
    if opcode == 0x89 { // MOV r/m16,r16
        if len(bytes[idx:]) < 1 {
            return {}, 0, false
        }
        modrm := (cast(^ModRM_Byte) &bytes[idx])^
        idx += 1
        rx_op, rm_op, modrm_len, ok := decode_modrm(bytes[idx:], modrm)
        if !ok {
            return {}, 0, false
        }
        idx += modrm_len
        res := Instruction {
            mnemonic = .Mov,
            flags = {.Direction_Bit},
            rx_op = rx_op,
            rm_op = rm_op,
        }
        return res, idx, true
    } else if opcode == 0x8b { // MOV r16,r/m16
        if len(bytes[idx:]) < 1 {
            return {}, 0, false
        }
        modrm := (cast(^ModRM_Byte) &bytes[idx])^
        idx += 1
        rx_op, rm_op, modrm_len, ok := decode_modrm(bytes[idx:], modrm)
        if !ok {
            return {}, 0, false
        }
        idx += modrm_len
        res := Instruction {
            mnemonic = .Mov,
            rx_op = rx_op,
            rm_op = rm_op,
        }
        return res, idx, true
    } else if opcode & 0xf8 == 0xb8 { // MOV r16,imm16
        if len(bytes[idx:]) < 2 {
            return {}, 0, false
        }
        r16 := opcode & 0x07
        imm16 := (cast(^u16le) &bytes[idx])^
        idx += 2
        res := Instruction {
            mnemonic = .Mov,
            extra_op = eop_imm16(imm16),
            rx_op = rx_gpreg16(r16)
        }
        return res, idx, true
    }
    return {}, 0, false
}

decode_modrm :: proc(bytes: []u8, modrm: ModRM_Byte) -> (RX_Op, RM_Op, int, bool) {
    Addr16_RM_Entry :: struct {
        base: u8,
        index: u8,
    }
    addr16_rm_table := []Addr16_RM_Entry {
        { base = REG_BX, index = REG_SI },
        { base = REG_BX, index = REG_DI },
        { base = REG_BP, index = REG_SI },
        { base = REG_BP, index = REG_DI },
        { base = REG_SI, index = REG_NONE },
        { base = REG_DI, index = REG_NONE },
        { base = REG_BP, index = REG_NONE },
        { base = REG_BX, index = REG_NONE },
    }
    rx_op := rx_gpreg16(modrm.rx)
    rm_op: RM_Op = ---
    modrm_size := 0
    if modrm.mod == 0b11 {
        rm_op = rm_gpreg16(modrm.rm)
    } else {
        entry := addr16_rm_table[modrm.rm]
        base := entry.base
        index := entry.index
        disp := i32(0)
        switch modrm.mod {
        case 0b00:
            if modrm.rm == 0b110 {
                if len(bytes) < 2 {
                    return {}, {}, 0, false
                }
                base = REG_NONE
                index = REG_NONE
                disp := cast(i32) ((cast(^i16le) &bytes[0])^)
                modrm_size = 2
            }
        case 0b01:
            if len(bytes) < 1 {
                return {}, {}, 0, false
            }
            disp = cast(i32) ((cast(^i8) &bytes[0])^)
            modrm_size = 1
        case 0b10:
            if len(bytes) < 2 {
                return {}, {}, 0, false
            }
            disp = cast(i32) ((cast(^i16le) &bytes[0])^)
            modrm_size = 2
        }
        rm_op = rm_mem16_addr16(base, index, disp)
    }
    return rx_op, rm_op, modrm_size, true
}

