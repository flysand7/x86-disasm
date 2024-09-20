package x86_disasm

DS_DEFAULT :: u8(0xff)

// For fields holding registers: The value that signifies the absense of
// a register, i.e. the `None` value.
REG_NONE :: u8(0xff)
REG_AX :: u8(0b000)
REG_CX :: u8(0b001)
REG_DX :: u8(0b010)
REG_BX :: u8(0b011)
REG_SP :: u8(0b100)
REG_BP :: u8(0b101)
REG_SI :: u8(0b110)
REG_DI :: u8(0b111)

REG_ES :: u8(0)
REG_CS :: u8(1)
REG_SS :: u8(2)
REG_DS :: u8(3)
REG_FS :: u8(4)
REG_GS :: u8(5)

// Instruction prefixes.
PREFIX_LOCK  :: u8(0xf0)
PREFIX_REPNZ :: u8(0xf2)
PREFIX_REPZ  :: u8(0xf3)
PREFIX_CS    :: u8(0x2e)
PREFIX_SS    :: u8(0x36)
PREFIX_DS    :: u8(0x3e)
PREFIX_ES    :: u8(0x26)
PREFIX_FS    :: u8(0x64)
PREFIX_GS    :: u8(0x65)
PREFIX_BT    :: u8(0x2e)
PREFIX_BN    :: u8(0x3e)
PREFIX_DATA  :: u8(0x66)
PREFIX_ADDR  :: u8(0x67)

// The REX byte.
REX_MAGIC :: u8(0x40)
REX_Byte :: bit_field u8 {
    b: u8 | 1,
    x: u8 | 1,
    r: u8 | 1,
    w: u8 | 1,
    magic: u8 | 4,
}

// The Mod/RM byte.
ModRM_Byte :: bit_field u8 {
    rm:  u8 | 3,
    rx:  u8 | 3,
    mod: u8 | 2,
}

// The SIB byte.
SIB_Byte :: bit_field u8 {
    sb: u8 | 3,
    si: u8 | 3,
    ss: u8 | 2,
}


CPU_Mode :: enum {
    Mode_16,
    Mode_32,
    Mode_64,
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
    SReg,
}

RX_Op :: struct {
    kind: RX_Op_Kind,
    size: u8,
    reg: u8,
}

rx_op :: proc(kind: RX_Op_Kind, size: u8, reg: u8) -> RX_Op {
    return RX_Op {
        kind = kind,
        size = size,
        reg = reg,
    }
}

RM_Op_Kind :: enum u8 {
    None,
    Mem_Addr_16,
    Mem_Addr_32,
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

rm_op :: proc(kind: RM_Op_Kind, size: u8, reg: u8) -> RM_Op {
    return RM_Op {
        kind = kind,
        size = size,
        reg = reg,
    }
}

rm_disp :: proc(size: u8, disp: i32) -> RM_Op {
    return RM_Op {
        size = size,
        base_reg = REG_NONE,
        index_reg = REG_NONE,
        scale = 1,
        disp = disp,
    }
}

rm_mem16 :: proc(size: u8, base_reg: u8, index_reg: u8, disp: i32) -> RM_Op {
    return RM_Op {
        kind = .Mem_Addr_16,
        size = size,
        base_reg = base_reg,
        index_reg = index_reg,
        scale = 1, // No scae in 16-bit addressing
        disp = disp,
    }
}

rm_mem32 :: proc(size: u8, base_reg: u8, index_reg: u8, scale: u8, disp: i32) -> RM_Op {
    return RM_Op {
        kind = .Mem_Addr_32,
        size = size,
        base_reg = base_reg,
        index_reg = index_reg,
        scale = scale,
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

eop_imm :: proc(size: u8, value: u64) -> EOP {
    return EOP {
        kind = .Imm,
        size = 2,
        lo = value,
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

