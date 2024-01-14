package disasm

import "core:fmt"
import "table"
import "generated_table"

Error :: enum {
    None,
    Trunc, // An valid encoding may have been found if more bytes were given.
    No_Encoding, // An encoding could not be found for given bytes.
    Invalid, // An encoding was valid up until a point where an invalid field was detected.
}

CPU_Mode :: enum {
    Mode_16,
    Mode_32,
    Mode_64,
}

cpu_mode_to_size :: proc(mode: CPU_Mode) -> Size {
    return cast(Size) (u8(mode)+2)
}

/*
    Scans the byte range corresponding to a single instruction.
    Returns the length of the byte range.
*/
pre_decode :: proc(cpu: CPU_Mode, bytes: []u8) -> (int, table.Encoding, Error) {
    idx := 0
    as_pfx := false
    ds_pfx := table.Data_Prefix.Prefix_Np
    scan_prefixes: for idx < len(bytes) {
        switch bytes[idx] {
            case 0xf0:
            case 0x26, 0x2e, 0x36, 0x3e, 0x65, 0x64:
            case 0xf2: ds_pfx = .Prefix_F2
            case 0xf3: ds_pfx = .Prefix_F3
            case 0x66: ds_pfx = .Prefix_66
            case 0x67: as_pfx = true
            case: break scan_prefixes
        }
        idx += 1
    }
    if idx == len(bytes) {
        return idx, {}, .Trunc
    }
    rex_w := b8(false)
    if bytes[idx] & 0xf0 == 0x40 {
        rex := bytes[idx]
        rex_w = (rex>>3)&0b1!=0
        idx += 1
    }
    if idx == len(bytes) {
        return idx, {}, .Trunc
    }
    op_pfx := table.Opcode_Prefix.None
    vex_w := b8(false)
    vex_p := b8(false)
    vex_v := u8(0)
    if cpu == .Mode_64 && bytes[idx] == 0xc5 {
        if len(bytes) < 2 {
            return idx, {}, .Trunc
        }
        vex_p = true
        b1 := bytes[idx+1]
        switch b1 & 0b11 {
            case 0b01: ds_pfx = .Prefix_66
            case 0b10: ds_pfx = .Prefix_F3
            case 0b11: ds_pfx = .Prefix_F2
        }
        idx += 2
    } else if cpu == .Mode_64 && bytes[idx] == 0xc4 {
        if len(bytes) < 3 {
            return idx, {}, .Trunc
        }
        vex_p = true
        b1 := bytes[idx+1]
        b2 := bytes[idx+2]
        switch b1 & 0b11111 {
            case 0b00010: op_pfx = .Opcode_0f38
            case 0b00011: op_pfx = .Opcode_0f3a
            case 0b00001: op_pfx = .Opcode_0f
            case: return idx, {}, .Trunc
        }
        switch b2 & 0b11 {
            case 0b01: ds_pfx = .Prefix_66
            case 0b10: ds_pfx = .Prefix_F3
            case 0b11: ds_pfx = .Prefix_F2
        }
        idx += 3
    } else if bytes[idx] == 0x0f {
        idx += 1
        op_pfx = .Opcode_0f
        if idx < len(bytes) {
            if bytes[idx] == 0x38 {
                op_pfx = .Opcode_0f38
                idx += 1
            } else if bytes[idx] == 0x3a {
                op_pfx = .Opcode_0f3a
                idx += 1
            }
        }
    }
    if idx == len(bytes) {
        return idx, {}, .Trunc
    }
    opcode := bytes[idx]
    idx += 1
    pfx_idx := table.make_pfx_line(
        bool(vex_p),
        ds_pfx,
        op_pfx,
    )
    encoding := transmute(table.Encoding) generated_table.encodings[pfx_idx][opcode]
    if encoding.mnemonic == 0 {
        return idx, {}, .No_Encoding
    }
    maybe_modrm_idk := u8(0)
    if idx < len(bytes) {
        maybe_modrm_idk = bytes[idx]
    }
    if .Rx_Ext in table.encoding_flags(encoding) {
        ext_slice_idx := encoding.mnemonic
        encoding = transmute(table.Encoding) generated_table.rx_ext_table[ext_slice_idx][(maybe_modrm_idk>>3)&0b111]
    }
    addr_size := cpu_mode_to_size(cpu)
    data_size := cpu_mode_to_size(cpu)
    switch cpu {
        case .Mode_16:
            if as_pfx { addr_size = .Size_32 }
            if ds_pfx == .Prefix_66 { data_size = .Size_32 }
        case .Mode_32:
            if as_pfx { addr_size = .Size_16 }
            if ds_pfx == .Prefix_66 { data_size = .Size_16 }
        case .Mode_64:
            data_size = .Size_32
            if as_pfx { addr_size = .Size_32 }
            if rex_w { data_size = .Size_64 }
            else if ds_pfx == .Prefix_66 { data_size = .Size_16 }
    }
    if table.encoding_mod_kind(encoding) != .None {
        if idx == len(bytes) {
            return idx, {}, .Trunc
        }
        modrm := bytes[idx]
        idx += 1
        mod := modrm >> 6
        rm := modrm & 0b111
        disp := Size.Default
        if mod == 0b00 && rm == 0b101 {
            if addr_size == .Size_16 {
                disp = .Size_16
            } else {
                disp = .Size_32
            }
        } else if mod == 0b01 {
            disp = .Size_8
        } else if mod == 0b10 {
            if addr_size == .Size_16 {
                disp = .Size_16
            } else {
                disp = .Size_32
            }
        }
        if mod != 0b11 && rm == 0b100 {
            if idx == len(bytes) {
                return idx, {}, .Trunc
            }
            sib := bytes[idx]
            idx += 1
            if sib&0b111 == 0b101 {
                if mod == 0b00 || mod == 0b10 {
                    disp = .Size_32
                } else {
                    disp = .Size_8
                }
            }
        }
        if disp != .Default {
            disp_sz := table.size_to_bytes(disp)
            if idx+disp_sz-1 >= len(bytes) {
                return idx, {}, .Trunc
            }
            idx += disp_sz
        }
    }
    eop_len := 0
    switch table.encoding_extra_op(encoding) {
        case .Imm8: eop_len = 1
        case .Imm16: eop_len = 2
        case .Imm32: eop_len = 4
        case .Imm_R: eop_len = table.size_to_bytes(data_size)
        case .Imm:
            #partial switch data_size {
                case .Size_16: eop_len = 2
                case: eop_len = 4
            }
        case .Imm16imm8: eop_len = 3
        case .Rel8: eop_len = 1
        case .Rel16: eop_len = 2 
        case .Rel32: eop_len = 4
        case .Rel:
            #partial switch addr_size {
                case .Size_16: eop_len = 2
                case .Size_32, .Size_64: eop_len = 4
            }
        case .Far16: eop_len = 4
        case .Far32: eop_len = 6
        case .Far:
            #partial switch addr_size {
                case .Size_16: eop_len = 4
                case .Size_32, .Size_64: eop_len = 6
            }
        case .Xmmimm: eop_len = 1
        case .None:
    }
    if idx+eop_len-1 >= len(bytes) {
        return idx, {}, .Trunc
    }
    return idx+eop_len, encoding, .None
}

decode :: proc(cpu: CPU_Mode, bytes: []u8, encoding: table.Encoding) -> (Inst, bool) {
    ds_pfx := table.Data_Prefix.Prefix_Np
    as_pfx := false
    idx := 0
    lk_pfx := false
    seg := Reg {}
    parse_prefixes: for {
        switch bytes[idx] {
            case 0xf0: lk_pfx = true
            case 0x26: seg = Reg { .Sreg, .Size_16, 0 }
            case 0x2e: seg = Reg { .Sreg, .Size_16, 1 }
            case 0x36: seg = Reg { .Sreg, .Size_16, 2 }
            case 0x3e: seg = Reg { .Sreg, .Size_16, 3 }
            case 0x65: seg = Reg { .Sreg, .Size_16, 4 }
            case 0x64: seg = Reg { .Sreg, .Size_16, 5 }
            case 0xf2: ds_pfx = .Prefix_F2
            case 0xf3: ds_pfx = .Prefix_F3
            case 0x66: ds_pfx = .Prefix_66
            case 0x67: as_pfx = true
            case: break parse_prefixes
        }
        idx += 1
    }
    rex_r := false
    rex_b := false
    rex_x := false
    rex_w := false
    vex_w := false
    vex_l := false
    vex_p := false
    vex_v := u8(0)
    if bytes[idx] & 0xf0 == 0x40 {
        rex := bytes[idx]
        rex_w = (rex>>3)&1!=0
        rex_r = (rex>>2)&1!=0
        rex_x = (rex>>1)&1!=0
        rex_b = rex&1!=0
        idx += 1
    }
    op_pfx := table.Opcode_Prefix.None
    if cpu == .Mode_64 && bytes[idx] == 0xc5 {
        b1 := bytes[idx+1]
        vex_p = true
        rex_r = (b1 >> 7) == 0
        vex_v = (b1 >> 3) & 0b1111
        vex_l = ((b1>>2)&0b11)!=0
        switch b1 & 0b11 {
            case 0b01: ds_pfx = .Prefix_66
            case 0b10: ds_pfx = .Prefix_F3
            case 0b11: ds_pfx = .Prefix_F2
        }
        idx += 2
    } else if cpu == .Mode_64 && bytes[idx] == 0xc4 {
        b1 := bytes[idx+1]
        b2 := bytes[idx+2]
        vex_p = true
        rex_r = (b1>>7) == 0
        rex_x = ((b1>>6) & 0b1) == 0
        rex_b = ((b1>>5) & 0b1) == 0
        vex_w = (b2>>7) != 0
        vex_v = ((b2>>3)&0b1111)
        vex_l = ((b2>>2)&0b11)!=0
        rex_w ||= vex_w
        switch b1 & 0b11111 {
            case 0b00010: op_pfx = .Opcode_0f38
            case 0b00011: op_pfx = .Opcode_0f3a
            case 0b00001: op_pfx = .Opcode_0f
        }
        switch b2 & 0b11 {
            case 0b01: ds_pfx = .Prefix_66
            case 0b10: ds_pfx = .Prefix_F3
            case 0b11: ds_pfx = .Prefix_F2
        }
        idx += 3
    } else if bytes[idx] == 0x0f {
        idx += 1
        if idx < len(bytes) {
            if bytes[idx] == 0x38 {
                idx += 1
            } else if bytes[idx] == 0x3a {
                idx += 1
            }
        }
    }
    addr_size := cpu_mode_to_size(cpu)
    data_size := cpu_mode_to_size(cpu)
    switch cpu {
        case .Mode_16:
            if as_pfx { addr_size = .Size_32 }
            if ds_pfx == .Prefix_66 { data_size = .Size_32 }
        case .Mode_32:
            if as_pfx { addr_size = .Size_16 }
            if ds_pfx == .Prefix_66 { data_size = .Size_16 }
        case .Mode_64:
            data_size = .Size_32
            if as_pfx { addr_size = .Size_32 }
            if rex_w { data_size = .Size_64 }
            else if ds_pfx == .Prefix_66 { data_size = .Size_16 }
    }
    opcode := bytes[idx]
    idx += 1
    has_modrm := false
    modrm := u8(0)
    encoding := encoding
    assert(.Rx_Ext not_in table.encoding_flags(encoding))
    if table.encoding_mod_kind(encoding) != .None {
        has_modrm = true
        modrm = bytes[idx]
        idx += 1
    }
    mods := bit_set[table.Mod] {}
    if has_modrm {
        mods = transmute(bit_set[table.Mod]) u8(u8(1)<<u8(modrm>>6))
    }
    if .Is_Slice in table.encoding_flags(encoding) {
        cst_mask := table.cst_mask(table.make_cst_line_specific(vex_w, mods, cpu_mode_to_size(cpu), data_size, addr_size))
        encodings := generated_table.slice_table[table.encoding_slice_index(encoding)]
        found := false
        find_encoding: for e in encodings {
            e := transmute(table.Encoding) e
            if table.encoding_cst_mask(e) & cst_mask != cst_mask {
                continue
            }
            #partial switch table.encoding_mod_kind(e) {
                case .None, .Normal:
                    encoding = e
                    found = true
                    break find_encoding
                case .Opcode:
                    mod, _, rm := table.encoding_modrm(e)
                    e_mod := modrm>>6
                    e_rm := modrm&0b111
                    if mod == e_mod && rm == e_rm {
                        encoding = e
                        found = true
                        break find_encoding
                    }
                case .Opcode_Ext:
                    encoding = e
                    found = true
                    break find_encoding
            }
        }
        if !found {
            return {}, false
        }
    }
    assert(.Is_Slice not_in table.encoding_flags(encoding), "Found encoding was a slice..?")
    inst := Inst {
        mnemonic = generated_table.string_table[table.encoding_mnemonic_idx(encoding)],
        length = len(bytes),
        seg = seg,
    }
    flags := table.encoding_flags(encoding)
    if .Rep in flags {
        if ds_pfx == .Prefix_F3 {
            if opcode != 0xaf {
                inst.flags += {.Rep}
            } else {
                inst.flags += {.Repz}
            }
        } else if ds_pfx == .Prefix_F2 {
            inst.flags += {.Repnz}
        }
    }
    if .W in flags {
        data_size = .Size_8
    }
    if vex_p {
        if vex_l {
            data_size = .Size_256
        } else {
            data_size = .Size_128
        }
    }
    if dov := table.encoding_data_override(encoding); dov != .Default {
        data_size = dov
    }
    switch table.encoding_mod_kind(encoding) {
        case .None:
        case .Opcode:
        case .Normal:
            rx_type := table.encoding_rx_type(encoding)
            rx_op := rx_operand_r(vex_l, rex_b, data_size, rx_type, (modrm>>3)&0b111)
            rm_op, sz := rm_operand(bytes[idx:], encoding, addr_size, data_size, modrm)
            add_operand(&inst, rx_op)
            add_operand(&inst, rm_op)
            idx += sz
        case .Opcode_Ext:
            rm_op, sz := rm_operand(bytes[idx:], encoding, addr_size, data_size, modrm)
            add_operand(&inst, rm_op)
            idx += sz
    }
    if .Rx_Value in flags {
        rx_type := table.encoding_rx_type(encoding)
        rx_size := table.encoding_rx_size(encoding, data_size)
        rx := table.encoding_rx(encoding)
        add_operand(&inst, rx_operand_r(vex_l, rex_r, data_size, rx_type, rx))
    }
    if .D in flags {
        if inst.op_count != 2 {
        }
        inst.op[0], inst.op[1] = inst.op[1], inst.op[0]
    }
    if vex_p && .Vex_Vz not_in flags {
        add_operand(&inst, vex_operand(vex_l, vex_v))
    }
    switch table.encoding_extra_op(encoding) {
        case .None: break
        case .Imm8:  add_operand(&inst, Imm { cast(i64) (transmute(^i8) raw_data(bytes[idx:]))^ })
        case .Imm16: add_operand(&inst, Imm { cast(i64) (transmute(^i16) raw_data(bytes[idx:]))^ })
        case .Imm32: add_operand(&inst, Imm { cast(i64) (transmute(^i32) raw_data(bytes[idx:]))^ })
        case .Imm_R:
            #partial switch data_size {
                case .Size_16: add_operand(&inst, Imm { cast(i64) (transmute(^i16) raw_data(bytes[idx:]))^ })
                case .Size_32: add_operand(&inst, Imm { cast(i64) (transmute(^i32) raw_data(bytes[idx:]))^ })
                case .Size_64: add_operand(&inst, Imm { cast(i64) (transmute(^i64) raw_data(bytes[idx:]))^ })
                case: unreachable()
            }
        case .Imm:
            #partial switch data_size {
                case .Size_16: add_operand(&inst, Imm { cast(i64) (transmute(^i16) raw_data(bytes[idx:]))^ })
                case .Size_32: add_operand(&inst, Imm { cast(i64) (transmute(^i32) raw_data(bytes[idx:]))^ })
                case .Size_64: add_operand(&inst, Imm { cast(i64) (transmute(^i32) raw_data(bytes[idx:]))^ })
                case: unreachable()
            }
        case .Imm16imm8:
            add_operand(&inst, Imm { cast(i64) (transmute(^i16) raw_data(bytes[idx:]))^ })
            add_operand(&inst, Imm { cast(i64) (transmute(^i8) raw_data(bytes[idx+2:]))^ })
        case .Rel8:  add_operand(&inst, Mem_Short { (transmute(^i8) raw_data(bytes[idx:]))^ })
        case .Rel16: add_operand(&inst, Mem_Near { data_size, cast(i32) (transmute(^i16) raw_data(bytes[idx:]))^ })
        case .Rel32: add_operand(&inst, Mem_Near { data_size, cast(i32) (transmute(^i32) raw_data(bytes[idx:]))^ })
        case .Rel:
            #partial switch addr_size {
                case .Size_16: add_operand(&inst, Mem_Near { data_size, cast(i32) (transmute(^i16) raw_data(bytes[idx:]))^ })
                case .Size_32: fallthrough
                case .Size_64: add_operand(&inst, Mem_Near { data_size, cast(i32) (transmute(^i32) raw_data(bytes[idx:]))^ })
            }
        case .Far16:
            add_operand(&inst, Mem_Far {
                data_size,
                (transmute(^u16) raw_data(bytes[idx:]))^,
                cast(i32) (transmute(^i16) raw_data(bytes[idx+2:]))^,
            })
        case .Far32: 
            add_operand(&inst, Mem_Far {
                data_size,
                (transmute(^u16) raw_data(bytes[idx:]))^,
                (transmute(^i32) raw_data(bytes[idx+2:]))^,
            })
        case .Far:
            #partial switch addr_size {
                case .Size_16:
                    add_operand(&inst, Mem_Far {
                        data_size,
                        (transmute(^u16) raw_data(bytes[idx:]))^,
                        cast(i32) (transmute(^i16) raw_data(bytes[idx+2:]))^,
                    })
                case .Size_32: fallthrough
                case .Size_64:
                    add_operand(&inst, Mem_Far {
                        data_size,
                        (transmute(^u16) raw_data(bytes[idx:]))^,
                        (transmute(^i32) raw_data(bytes[idx+2:]))^,
                    })
            }
        case .Xmmimm: 
            imm := (transmute(^u8) raw_data(bytes[idx:]))^
            add_operand(&inst, Reg {
                .Xmm,
                data_size,
                imm>>4,
            })
    }
    return inst, true
}

rm_operand :: proc(buf: []u8, e: table.Encoding, as, ds: Size, modrm: u8) -> (Operand, int) {
    mod := modrm>>6
    rm := modrm&0b111
    rmt := table.encoding_rm_type(e)
    rms := table.encoding_rm_size(e, mod, ds)
    if mod == 0b11 {
        return Reg { rmt, rms, rm }, 0
    }
    if as == .Size_16 {
        base_regs: [8]struct{base: Reg, index: Reg} = {
            {base = {.Reg, .Size_16, 3}, index = {.Reg, .Size_16, 6}},
            {base = {.Reg, .Size_16, 3}, index = {.Reg, .Size_16, 7}},
            {base = {.Reg, .Size_16, 5}, index = {.Reg, .Size_16, 6}},
            {base = {.Reg, .Size_16, 5}, index = {.Reg, .Size_16, 7}},
            {base = {.Reg, .Size_16, 6}, index = {}},
            {base = {.Reg, .Size_16, 7}, index = {}},
            {base = {.Reg, .Size_16, 5}, index = {}},
            {base = {.Reg, .Size_16, 3}, index = {}},
        }
        pair := base_regs[rm]
        base := pair.base
        index := pair.index
        disp := i32(0)
        consumed := 0
        if mod == 0b01 {
            disp = cast(i32) (transmute(^u8) raw_data(buf))^
            consumed = 1
        } else if (mod == 0b00 && rm == 0b110) || mod == 0b10 {
            disp = cast(i32) (transmute(^u16le) raw_data(buf))^
            consumed = 2
            if mod == 0b00 && rm == 0b110 {
                index = {}
                base  = {}
            }
        }
        return Mem { rms, base, index, disp, 1 }, consumed
    } else {
        consumed := 0
        base := Reg {}
        index := Reg {}
        scale := 0
        disp := i32(0)
        if rm == 0b100 {
            sib := (transmute(^u8) raw_data(buf))^
            consumed += 1
            ss := sib>>6
            si := (sib>>3)&0b111
            sb := sib&0b111
            if si != 0b100 {
                index = Reg { .Reg, as, si }
            } else {
                scale = 1<<si
            }
            if sb == 0b101 {
                if mod == 0b00 {
                    disp = (transmute(^i32) raw_data(buf[consumed:]))^
                    consumed += 4
                } else if mod == 0b01 {
                    base = Reg { .Reg, as, sb }
                    disp = cast(i32) (transmute(^i8) raw_data(buf[consumed:]))^
                    consumed += 1
                } else if mod == 0b10 {
                    base = Reg { .Reg, as, sb }
                    disp = (transmute(^i32) raw_data(buf[consumed:]))^
                    consumed += 4
                }
            } else {
                base = Reg { .Reg, as, sb }
            }
        } else if !(mod == 0b00 && rm == 0b101) {
            base = Reg { .Reg, as, rm }
        }
        switch mod {
            case 0b00:
                if rm == 0b101 {
                    disp = (transmute(^i32) raw_data(buf[consumed:]))^
                    consumed += 4
                    if as == .Size_64 {
                        base = Reg { .Extras, .Size_64, 0 }
                    }
                }
            case 0b01:
                disp = cast(i32) (transmute(^u8) raw_data(buf[consumed:]))^
                consumed += 1
            case 0b10:
                disp = (transmute(^i32) raw_data(buf[consumed:]))^
                consumed += 4
        }
        return Mem { rms, base, index, disp, 1 }, consumed
    }
}

rx_operand_b :: proc(vex_l, rex_b: bool, ds: Size, rxt: Reg_Set, rxi: u8) -> Operand {
    if rxt == .Reg {
        rxi := rxi
        if rex_b {
            rxi |= 0b1000
        }
        return Reg { rxt, ds, rxi }
    } else if rxt == .Xmm {
        rxi := rxi
        if vex_l {
            rxi |= 0b1000
        }
        return Reg { rxt, ds, rxi }
    } else {
        return Reg { rxt, default_size_for_reg_kind(rxt), rxi }
    }
}

rx_operand_r :: proc(vex_l, rex_b: bool, ds: Size, rxt: Reg_Set, rxi: u8) -> Operand {
    if rxt == .Reg {
        rxi := rxi
        if rex_b {
            rxi |= 0b1000
        }
        return Reg { rxt, ds, rxi }
    } else if rxt == .Xmm {
        rxi := rxi
        if vex_l {
            rxi |= 0b1000
        }
        return Reg { rxt, ds, rxi }
    } else {
        return Reg { rxt, default_size_for_reg_kind(rxt), rxi }
    }
}

vex_operand :: proc(vex_l: bool, vex_v: u8) -> Operand {
    return Reg { .Xmm, vex_l? .Size_256 : .Size_128, vex_v }
}

default_size_for_reg_kind :: proc(s: Reg_Set) -> Size {
    switch s {
        case .Bndreg: return .Size_8  // TODO
        case .Creg:   return .Size_8  // TODO
        case .Dreg:   return .Size_8  // TODO
        case .St:     return .Size_64 // TODO
        case .Sreg:   return .Size_16
        case .Mmx:    return .Size_64 // TODO
        case .Extras: unreachable()
        case .Reg, .Xmm:
            panic("GPRs and XMMs dont have default size")
    }
    unreachable()
}
