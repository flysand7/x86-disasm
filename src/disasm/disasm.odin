package x86_disasm

cpu_mode := CPU_Mode.Mode_16

set_cpu_mode :: proc(mode: CPU_Mode) {
    cpu_mode = mode
}

disasm_all :: proc(bytes: []u8) -> [dynamic]Instruction {
    insts := make([dynamic]Instruction)
    bytes := bytes
    for instruction in disasm_one(bytes) {
        append(&insts, instruction)
        bytes = bytes[instruction.size:]
    }
    return insts
}

disasm_one :: proc(bytes: []u8) -> (res: Instruction, ok: bool) {
    idx := 0
    if len(bytes) == 0 {
        return {}, false
    }
    ds := u8(2)
    as := u8(2)
    seg := REG_NONE
    parse_prefixes: for {
        switch bytes[idx] {
        case PREFIX_ADDR: as = 4
        case PREFIX_DATA: ds = 4
        case PREFIX_DS: seg = REG_DS
        case PREFIX_CS: seg = REG_CS
        case PREFIX_ES: seg = REG_ES
        case: break parse_prefixes
        }
        idx += 1
    }
    opcode := bytes[idx]
    idx += 1
    // Stage 1 decoding
    stage1_entry := stage1_table[opcode]
    (stage1_entry.entry_idx != 0) or_return
    if stage1_entry.force_ds != DS_DEFAULT {
        ds = stage1_entry.force_ds
    }
    modrm: Parsed_ModRM
    modrm_byte: ModRM_Byte
    implicit_rm := false
    if stage1_entry.kind == .Mod_Rm || stage1_entry.kind == .Rx_Extend {
        (len(bytes[idx:]) >= 1) or_return
        modrm_byte = (cast(^ModRM_Byte) &bytes[idx])^
        idx += 1
        sz: int
        modrm, sz = decode_modrm(bytes[idx:], modrm_byte, as) or_return
        idx += sz
    }
    eop: EOP
    switch stage1_entry.eop  {
    case .None:
    case .Imm8:
        (len(bytes[idx:]) >= 1) or_return
        imm := u64((cast(^u8) &bytes[idx])^)
        eop = eop_imm(1, imm)
        idx += 1
    case .Imm:
        (len(bytes[idx:]) >= int(ds)) or_return
        imm: u64
        switch ds {
            case 1: imm = u64((cast(^u8) &bytes[idx])^)
            case 2: imm = u64((cast(^u16le) &bytes[idx])^)
            case 4: imm = u64((cast(^u32le) &bytes[idx])^)
            case: panic("Unknown data size")
        }
        eop = eop_imm(ds, imm)
        idx += int(ds)
    case .SAddr:
        (len(bytes[idx:]) >= 1) or_return
        offset := (cast(^i8) &bytes[idx])^
        idx += 1
        eop = eop_saddr(offset)
    case .FAddr:
        (len(bytes[idx:]) >= 2+int(as)) or_return
        seg := u16((cast(^u16le) &bytes[idx])^)
        idx += 2
        disp: i32
        switch as {
            case 2: disp = i32((cast(^i16le) &bytes[idx])^)
            case 4: disp = i32((cast(^i32le) &bytes[idx])^)
            case: panic("Unknown data size")
        }
        idx += int(as)
        eop = eop_faddr(as, seg, disp)
    case .NAddr:
        (len(bytes[idx:]) >= int(as)) or_return
        disp: i32
        switch as {
            case 2: disp = i32((cast(^i16le) &bytes[idx])^)
            case 4: disp = i32((cast(^i32le) &bytes[idx])^)
            case: panic("Unknown data size")
        }
        idx += int(as)
        eop = eop_naddr(as, disp)
    case .Disp:
        (len(bytes[idx:]) >= int(as)) or_return
        disp: i32
        switch as {
            case 2: disp = i32((cast(^i16le) &bytes[idx])^)
            case 4: disp = i32((cast(^i32le) &bytes[idx])^)
            case: panic("Unknown data size")
        }
        idx += int(as)
        implicit_rm = true
        modrm = Parsed_ModRM {
            size = as,
            base = REG_NONE,
            index = REG_NONE,
            scale = 1,
            disp = disp,
        }
    }
    // Stage 2 decoding
    encoding := Encoding {}
    mnemonic: Mnemonic
    if stage1_entry.kind == .Rx_Extend {
        rx_stage := rx_ext_table[stage1_entry.entry_idx][modrm_byte.rx]
        encoding = stage2_table[rx_stage.entry_idx]
        mnemonic = rx_stage.mnemonic
    } else {
        encoding = stage2_table[stage1_entry.entry_idx]
        mnemonic = stage1_entry.mnemonic
    }
    rx: RX_Op
    rm: RM_Op
    if stage1_entry.kind == .Mod_Rm {
        rx = rx_op(encoding.rx_kind, ds, modrm_byte.rx)
    }
    if stage1_entry.kind == .Mod_Rm || stage1_entry.kind == .Rx_Extend {
        switch modrm.size {
        case 0: rm = rm_op(encoding.rm_kind, ds, modrm_byte.rm)
        case 8: rm = rm_mem8(modrm.disp)
        case 2: rm = rm_mem16(ds, modrm.base, modrm.index, modrm.disp)
        case 4: rm = rm_mem32(ds, modrm.base, modrm.index, modrm.scale, modrm.disp)
        case: unreachable()
        }
    }
    if implicit_rm {
        rm = rm_disp(ds, modrm.disp)
    }
    if stage1_entry.kind == .Rx_Embed || stage1_entry.kind == .None {
        if encoding.rx_value != REG_NONE {
            rx = rx_op(encoding.rx_kind, ds, encoding.rx_value)
        }
    }
    flags: bit_set[Instruction_Flag]
    if .D in encoding.flags {
        flags += {.Direction_Bit}
    }
    {
        if opcode == 0xff && (modrm_byte.rx == 3 || modrm_byte.rx == 5) {
            flags += {.Far}
        }
        if opcode == 0xcb || opcode == 0xca {
            flags += {.Far}
        }
        if opcode == 0xd0 {
            eop = eop_imm(1, 1)
        }
        if opcode == 0xd2 {
            rx = rx_op(.GPReg, 1, REG_CX)
        }
    }
    res = Instruction {
        mnemonic = mnemonic,
        seg = seg,
        flags = flags,
        rx_op = rx,
        rm_op = rm,
        extra_op = eop,
    }
    res.size = idx
    ok = true
    return
}

Parsed_ModRM :: struct {
    size: u8, // if 0, base has register, other fields not used
    base: u8,
    index: u8,
    scale: u8,
    disp: i32,
}

decode_modrm :: proc(bytes: []u8, modrm: ModRM_Byte, as: u8) -> (Parsed_ModRM, int, bool) {
    switch as {
    case 4: return decode_modrm_addr32(bytes, modrm)
    case 2: return decode_modrm_addr16(bytes, modrm)
    }
    panic("Unhandled addr size")
}

decode_modrm_addr16 :: proc(bytes: []u8, modrm: ModRM_Byte) -> (Parsed_ModRM, int, bool) {
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
    modrm_size := 0
    // Early return on mod=0b11
    if modrm.mod == 0b11 {
        parsed := Parsed_ModRM {
            size = 0,
            base = modrm.rm,
        }
        return parsed, modrm_size, true
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
        return {}, 0, false
    }
    // Parse displacement
    disp := i32(0)
    if disp_size == 1 {
        disp = cast(i32) ((cast(^i8) &bytes[modrm_size])^)
    } else if disp_size == 2 {
        disp = cast(i32) ((cast(^i16le) &bytes[modrm_size])^)
    }
    modrm_size += disp_size
    parsed := Parsed_ModRM {
        size = 2,
        base = base,
        index = index,
        scale = 1,
        disp = disp,
    }
    return parsed, modrm_size, true
}

decode_modrm_addr32 :: proc(bytes: []u8, modrm: ModRM_Byte) -> (Parsed_ModRM, int, bool) {
    modrm_size := 0
    // Early return on mod=0b11
    if modrm.mod == 0b11 {
        parsed := Parsed_ModRM {
            size = 0,
            base = modrm.rm,
        }
        return parsed, modrm_size, true
    }
    // If mod is 0b100, base comes from sib, as well as index and scale
    base := modrm.rm
    index := REG_NONE
    scale := u8(1)
    if modrm.rm == 0b100 {
        if len(bytes) < 2 {
            return {}, 0, false
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
        return {}, 0, false
    }
    // Parse displacement
    disp := i32(0)
    if disp_size == 1 {
        disp = cast(i32) ((cast(^i8) &bytes[modrm_size])^)
    } else if disp_size == 4 {
        disp = cast(i32) ((cast(^i32le) &bytes[modrm_size])^)
    }
    modrm_size += disp_size
    parsed := Parsed_ModRM {
        size  = 4,
        base = base,
        index = index,
        scale = scale,
        disp = disp,
    }
    return parsed, modrm_size, true
}
