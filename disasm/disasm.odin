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

rx_gpreg :: proc(size: u8, reg: u8) -> RX_Op {
    return RX_Op {
        kind = .GPReg,
        size = size,
        reg = reg,
    }
}

RM_Op_Kind :: enum u8 {
    None,
    Mem_Addr16,
    Mem_Addr32,
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

rm_gpreg :: proc(size: u8, reg: u8) -> RM_Op {
    return RM_Op {
        kind = .GPReg,
        size = size,
        reg = reg,
    }
}

rm_disp :: proc(size: u8, disp: i32) -> RM_Op {
    return RM_Op {
        kind = .Mem_Addr32,
        size = size,
        base_reg = REG_NONE,
        index_reg = REG_NONE,
        scale = 1,
        disp = disp,
    }
}

rm_mem16 :: proc(size: u8, base_reg: u8, index_reg: u8, disp: i32) -> RM_Op {
    return RM_Op {
        kind = .Mem_Addr16,
        size = size,
        base_reg = base_reg,
        index_reg = index_reg,
        scale = 1, // No scae in 16-bit addressing
        disp = disp,
    }
}

rm_mem32 :: proc(size: u8, base_reg: u8, index_reg: u8, scale: u8, disp: i32) -> RM_Op {
    return RM_Op {
        kind = .Mem_Addr32,
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

disasm_one :: proc(bytes: []u8) -> (res: Instruction, idx: int, ok: bool) {
    if len(bytes) == 0 {
        return {}, 0, false
    }
    ds := u8(2)
    as := u8(2)
    parse_prefixes: for {
        switch bytes[idx] {
        case PREFIX_ADDR: as = 4
        case PREFIX_DATA: ds = 4
        case: break parse_prefixes
        }
        idx += 1
    }
    opcode := bytes[idx]
    idx += 1
    has_modrm := false
    has_imm := false
    has_disp := false
    implicit_rx := REG_NONE
    opcode_rx := false
    if opcode == 0x89 { // MOV r/m16,r16
        has_modrm = true
    } else if opcode == 0x8b { // MOV r16,r/m16
        has_modrm = true
    } else if opcode & 0xf8 == 0xb8 { // MOV r16,imm16
        opcode_rx = true
        has_imm = true
    } else if opcode == 0xa0 { // MOV AX, [disp]
        implicit_rx = 0
        has_disp = true
    } else {
        return
    }
    rx_op: RX_Op
    rm_op: RM_Op
    eop: EOP
    if opcode_rx {
        r := opcode & 0x07
        rx_op = rx_gpreg(ds, r)
    }
    if has_modrm {
        (len(bytes[idx:]) >= 1) or_return
        modrm := (cast(^ModRM_Byte) &bytes[idx])^
        idx += 1
        sz: int
        rx_op, rm_op, sz = decode_modrm(bytes[idx:], modrm, as, ds) or_return
        idx += sz
    }
    if has_imm {
        (len(bytes[idx:]) >= int(ds)) or_return
        imm: u64
        switch ds {
            case 2: imm = u64((cast(^u16le) &bytes[idx])^)
            case 4: imm = u64((cast(^u32le) &bytes[idx])^)
            case: panic("Unknown data size")
        }
        idx += int(ds)
        eop = eop_imm(ds, imm)
    }
    if has_disp {
        (len(bytes[idx:]) >= int(ds)) or_return
        disp: i32
        switch as {
            case 2: disp = i32((cast(^i16le) &bytes[idx])^)
            case 4: disp = i32((cast(^i32le) &bytes[idx])^)
            case: panic("Unknown data size")
        }
        idx += int(as)
        rm_op = rm_disp(ds, disp)
    }
    res = Instruction {
        mnemonic = .Mov,
        rx_op = rx_op,
        rm_op = rm_op,
    }
    ok = true
    return
}

decode_modrm :: proc(bytes: []u8, modrm: ModRM_Byte, as: u8, ds: u8) -> (RX_Op, RM_Op, int, bool) {
    switch as {
    case 2: return decode_modrm_addr16(bytes, modrm, ds)
    case 4: return decode_modrm_addr32(bytes, modrm, ds)
    }
    panic("Unhandled addr size")
}

decode_modrm_addr16 :: proc(bytes: []u8, modrm: ModRM_Byte, ds: u8) -> (RX_Op, RM_Op, int, bool) {
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
    rx_op := rx_gpreg(ds, modrm.rx)
    modrm_size := 0
    // Early return on mod=0b11
    if modrm.mod == 0b11 {
        rm_op := rm_gpreg(ds, modrm.rm)
        return rx_op, rm_op, modrm_size, true
    }
    entry := addr16_rm_table[modrm.rm]
    base := entry.base
    index := entry.index
    // Find out displacement size
    disp_size := 0
    switch modrm.mod {
    case 0b00:
        if modrm.rm == 0b110 {
            base = REG_NONE
            index = REG_NONE
            disp_size = 2
        }
    case 0b01: disp_size = 1
    case 0b10: disp_size = 2
    }
    if len(bytes) < disp_size {
        return {}, {}, 0, false
    }
    // Parse displacement
    disp := i32(0)
    if disp_size == 1 {
        disp = cast(i32) ((cast(^i8) &bytes[modrm_size])^)
    } else if disp_size == 2 {
        disp = cast(i32) ((cast(^i16le) &bytes[modrm_size])^)
    }
    modrm_size += disp_size
    rm_op := rm_mem16(ds, base, index, disp)
    return rx_op, rm_op, modrm_size, true
}

decode_modrm_addr32 :: proc(bytes: []u8, modrm: ModRM_Byte, ds: u8) -> (RX_Op, RM_Op, int, bool) {
    rx_op := rx_gpreg(ds, modrm.rx)
    modrm_size := 0
    // Early return on mod=0b11
    if modrm.mod == 0b11 {
        rm_op := rm_gpreg(ds, modrm.rm)
        return rx_op, rm_op, modrm_size, true
    }
    // If mod is 0b100, base comes from sib, as well as index and scale
    base := modrm.rm
    index := REG_NONE
    scale := u8(1)
    if modrm.rm == 0b100 {
        if len(bytes) < 2 {
            return {}, {}, 0, false
        }
        sib := (cast(^SIB_Byte) &bytes[modrm_size])^
        if sib.si != 0b100 {
            scale = 1 << sib.ss
            index = sib.si
        }
        base = sib.sb
        modrm_size += 1
    }
    // Figure out the displacement size
    disp_size := 0
    switch modrm.mod {
    case 0b00:
        if base == 0b110 {
            base = REG_NONE
            index = REG_NONE
            disp_size = 4
        }
    case 0b01: disp_size = 1
    case 0b10: disp_size = 4
    }
    if len(bytes) < disp_size {
        return {}, {}, 0, false
    }
    // Parse displacement
    disp := i32(0)
    if disp_size == 1 {
        disp = cast(i32) ((cast(^i8) &bytes[modrm_size])^)
    } else if disp_size == 4 {
        disp = cast(i32) ((cast(^i32le) &bytes[modrm_size])^)
    }
    modrm_size += disp_size
    rm_op := rm_mem32(ds, base, index, scale, disp)
    return rx_op, rm_op, modrm_size, true
}
