package disasm_table

import "core:strings"
import "core:strconv"
import "core:slice"
import "core:fmt"
import "core:os"

PACKAGE_NAME :: "disasm_generated_table"
SRC_PATH :: "./data/table.txt"
DST_PATH :: "./src/disasm/generated_table/table.odin"

IND1 :: "    "
IND2 :: "        "
IND3 :: "            "
IND4 :: "                "

MOD_ALL :: bit_set[Mod] {.Mod_00, .Mod_01, .Mod_10, .Mod_11}

Encoding_Line :: struct {
    mnemonic: string,
    cst_line: CST_Line  `fmt:"b"`,
    pfx_line: u8 `fmt:"b"`,
    opcode:   u8 `fmt:"x"`,
    opcode_rx: u8 `fmt:"x"`,
    flg_line: FLG_Line,
    rmx_line: RMX_Line `fmt:"b"`,
    line_no:  u64,
}

Encoding_Ext :: struct {
    using e: Encoding,
    rx_ext: u8,
}

is_hex :: proc(b: string) -> bool {
    f :: proc(c: u8) -> bool {
        return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
    }
    return len(b) == 2 && f(b[0]) && f(b[1])
}

get_hex :: proc(b: string) -> u8 {
    f :: proc(c: u8) -> u8 {
        if '0' <= c && c <= '9' {
            return c - '0'
        } else {
            return c - 'a' + 10
        }
    }
    return f(b[0]) << 4 | f(b[1])
}

get_regset :: proc(s: string) -> Maybe(Reg_Set) {
    switch s {
        case "reg":    return .Reg
        case "mmx":    return .Mmx
        case "xmm":    return .Xmm
        case "sreg":   return .Sreg
        case "dreg":   return .Dreg
        case "creg":   return .Creg
        case "bndreg": return .Bndreg
        case "st":     return .St
    }
    return nil
}

get_extra_op_kind :: proc(s: string) -> Maybe(Extra_Operand_Kind) {
    switch s {
        case "imm8":      return .Imm8
        case "imm16":     return .Imm16
        case "imm32":     return .Imm32
        case "immr":      return .Imm_R
        case "imm":       return .Imm
        case "imm16imm8": return .Imm16imm8
        case "rel8":      return .Rel8
        case "rel16":     return .Rel16
        case "rel32":     return .Rel32
        case "rel":       return .Rel
        case "far16":     return .Far16
        case "far32":     return .Far32
        case "far":       return .Far
        case "xmmimm":    return .Xmmimm
    }
    return nil
}

get_size :: proc(line_no: int, s: string) -> Maybe(Size) {
    num, ok := strconv.parse_int(s)
    if !ok {
        fmt.eprintf("Error(%d): Bad size format\n", num)
        os.exit(1)
    }
    switch num {
        case 8:   return .Size_8
        case 16:  return .Size_16
        case 32:  return .Size_32
        case 64:  return .Size_64
        case 128: return .Size_128
        case 256: return .Size_256
        case 512: return .Size_512
    }
    return nil
}

parse_line :: proc(line_no: int, line: string) -> []Encoding_Line {
    parts := strings.split(line, " ")
    parts = slice.filter(parts, proc(part: string) -> bool {return len(part) > 0})
    if len(parts) < 1 {
        fmt.eprintf("Error(%d): Missing mnemonic\n", line_no)
        os.exit(1)
    }
    if len(parts) < 2 {
        fmt.eprintf("Error(%d): Missing spec for mnemonic\n", line_no)
        os.exit(1)
    }
    mnemonic := parts[0]
    vex := false
    dp_prefix := Maybe(Data_Prefix) {}
    op_prefix := Opcode_Prefix.None
    prefix_count := 0
    iterate_parts: for p, idx in parts[1:] {
        switch p {
        case "vp":
            if op_prefix == .None && dp_prefix == nil {
                vex = true
            } else {
                fmt.eprintf("Error(%d): vex prefix is not the first byte\n", line_no)
                os.exit(1)
            }
        case "np":
            if op_prefix == .None && dp_prefix == nil {
                dp_prefix = .Prefix_Np
            } else {
                fmt.eprintf("Error(%d): no prefix spec followed by opcode or data\n", line_no)
                os.exit(1)
            }
        case "66":
            if op_prefix == .None && dp_prefix == nil {
                dp_prefix = .Prefix_66
            }
        case "f3":
            if op_prefix == .None && dp_prefix == nil {
                dp_prefix = .Prefix_F3
            }
        case "f2":
            if op_prefix == .None && dp_prefix == nil {
                dp_prefix = .Prefix_F2
            }
        case "0f":
            if op_prefix == .None {
                op_prefix = .Opcode_0f
            }
        case "38":
            if op_prefix == .Opcode_0f {
                op_prefix = .Opcode_0f38
            }
        case "3a":
            if op_prefix == .Opcode_0f {
                op_prefix = .Opcode_0f3a
            }
        case:
            prefix_count = idx
            break iterate_parts
        }
    }
    if len(parts[1+prefix_count:]) < 0 {
        fmt.eprintf("Error(%d): Missing opcode\n", line_no)
        os.exit(1)
    }
    opcode := parts[1+prefix_count]
    extras := parts[1+prefix_count+1:]
    mod_kind := Mod_Kind.None
    rx_loop := false
    rmm := b8(false)
    rx_kind := Maybe(Reg_Set) {}
    rm_kind := Maybe(Reg_Set) {}
    rx_size := Size.Default
    rm_size := Size.Default
    rx_index := u8(0)
    opcode_rx := u8(0)
    flags := bit_set[Encoding_Flags; u8] {}
    cst_mod := MOD_ALL
    is_modrm_fixed := false
    if len(extras) > 0 && is_hex(extras[0]) {
        is_modrm_fixed = true
        modrm := get_hex(extras[0])
        // This part is weird but it basically just stores modrm fields
        // in the correct place of the rmx line and the constraints line.
        mod_kind = .Opcode
        opcode_rx = (modrm >> 3) & 0b111
        rx_size  = cast(Size) (modrm & 0b111)
        cst_mod = transmute(bit_set[Mod]) u8(1<<u8(modrm>>6))
        extras = extras[1:]
    }
    slash_idx := strings.index_byte(opcode, '/')
    plus_idx := strings.index_byte(opcode, '+')
    if slash_idx != -1 && plus_idx != -1 {
        fmt.eprintf("Error(%d): Opcode cannot have both modrm spec and register extension?\n", line_no)
        os.exit(1)
    }
    if slash_idx != -1 {
        if mod_kind != .None {
            fmt.eprintf("Error(%d): Instruction has two mod/rm bytes!\n", line_no)
            os.exit(1)
        }
        rx_spec := opcode[slash_idx+1:]
        if len(rx_spec) == 1 && '0' <= rx_spec[0] && rx_spec[0] <= '7' {
            mod_kind = .Opcode_Ext
            opcode_rx = rx_spec[0]-'0'
        } else if set, ok := get_regset(rx_spec).?; ok {
            mod_kind = .Normal
            rx_kind = set
        } else {
            fmt.eprintf("Error(%d): Missing or invalid /rx specification on opcode!\n", line_no)
            os.exit(1)
        }
        opcode = opcode[:slash_idx]
    } else if plus_idx != -1 {
        if set, ok := get_regset(opcode[plus_idx+1:]).?; ok {
            rx_kind = set
            opcode = opcode[:plus_idx]
            rx_loop = true
            flags += {.Rx_Value}
        } else {
            fmt.eprintf("Error(%d): Invalid +rx specification on opcode!\n", line_no)
            os.exit(1)
        }
    }
    if !is_hex(opcode) {
        fmt.eprintf("Error(%d): Opcode is not hex: %s\n", opcode)
        os.exit(1)
    }
    opcode_u8 := get_hex(opcode)
    eop := Extra_Operand_Kind.None
    data_size := Size.Default
    cst_cpu  := bit_set[Size] {.Size_16, .Size_32, .Size_64}
    cst_data := bit_set[Size] {.Size_16, .Size_32, .Size_64}
    cst_addr := bit_set[Size] {.Size_16, .Size_32, .Size_64}
    vexw := u8(0b11)
    for e in extras {
        assert(len(e) != 0)
        if op_kind, ok := get_extra_op_kind(e).?; ok {
            if eop != .None {
                fmt.eprintf("Error(%d): Multiple extra operands detected in an encoding: %v and %v\n", line_no, eop, op_kind)
                os.exit(1)
            }
            eop = op_kind
        } else if strings.has_prefix(e, "+") {
            flag := e[1:]
            flag_value := ""
            eq_idx := strings.index_byte(flag, '=')
            if eq_idx != -1 {
                if len(flag[eq_idx+1:]) == 0 {
                    fmt.eprintf("Error(%d): Empty flag value at %s\n", line_no, flag)
                    os.exit(1)
                }
                flag_value = flag[eq_idx+1:]
                flag = flag[:eq_idx]
                switch flag {
                case "rx":
                    if is_modrm_fixed {
                        fmt.eprintf("Error(%d): Cannot rx-extend fixed modrm encoding\n", line_no)
                        os.exit(1)
                    }
                    ok: bool
                    num_idx := -1
                    for v,i in flag_value {
                        if '0' <= v && v <= '9' {
                            num_idx = i
                            break
                        }
                    }
                    if num_idx != -1 {
                        rxi, ok := strconv.parse_int(flag_value[num_idx:])
                        if !ok {
                            fmt.eprintf("Error(%d): Bad register number: %s\n", line_no, flag_value[num_idx:])
                            os.exit(0)
                        }
                        rx_index = cast(u8) rxi
                    } else {
                        num_idx = 0
                    }
                    rx_kind, ok = get_regset(flag_value[:num_idx]).?
                    if !ok {
                        fmt.eprintf("Error(%d): Unknown register kind: %s\n", line_no, flag_value)
                        os.exit(0)
                    }
                    flags += {.Rx_Value}
                case "rm":
                    if is_modrm_fixed {
                        fmt.eprintf("Error(%d): Cannot override rm type in fixed modrm encoding\n", line_no)
                        os.exit(1)
                    }
                    ok: bool
                    rx_kind, ok = get_regset(flag_value).?
                    if !ok {
                        fmt.eprintf("Error(%d): Unknown register kind: %s\n", line_no, flag_value)
                        os.exit(0)
                    }
                case "rxs":
                    if is_modrm_fixed {
                        fmt.eprintf("Error(%d): Cannot override rx size in fixed modrm encoding\n", line_no)
                        os.exit(1)
                    }
                    ok: bool
                    rx_size, ok = get_size(line_no, flag_value).?
                    if !ok {
                        fmt.eprintf("Error(%d): Bad size: %s\n", line_no, flag_value)
                        os.exit(1)
                    }
                case "rms":
                    if is_modrm_fixed {
                        fmt.eprintf("Error(%d): Cannot override rm size in fixed modrm encoding\n", line_no)
                        os.exit(1)
                    }
                    ok: bool
                    rm_size, ok = get_size(line_no, flag_value).?
                    if !ok {
                        fmt.eprintf("Error(%d): Bad size: %s\n", line_no, flag_value)
                        os.exit(1)
                    }
                }
            } else {
                switch flag {
                    case "d":     flags += {.D}
                    case "w":     flags += {.W}
                    case "vexvz": flags += {.Vex_Vz}
                    case "far":   flags += {.Far}
                    case "rep":   flags += {.Rep}
                    case "ds64":  data_size = .Size_64
                    case "ds32":  data_size = .Size_32
                    case "ds16":  data_size = .Size_16
                    case "rx":
                        fmt.eprintf("Error(%d): +rx flag has no operand\n", line_no)
                        os.exit(1)
                    case "rm":
                        fmt.eprintf("Error(%d): +rm flag has no operand\n", line_no)
                        os.exit(1)
                    case "rxs":
                        fmt.eprintf("Error(%d): +rxs flag has no operand\n", line_no)
                        os.exit(1)
                    case "rms":
                        fmt.eprintf("Error(%d): +rms flag has no operand\n", line_no)
                        os.exit(1)
                }
            }
        } else if strings.has_prefix(e, "@") {
            c := e[1:]
            switch c {
                case "m64":   cst_cpu  = {.Size_64}
                case "mcl":   cst_cpu  = {.Size_32}
                case "ds64":  cst_data = {.Size_64}
                case "ds32":  cst_data = {.Size_32}
                case "ds16":  cst_data = {.Size_16}
                case "dn64":  cst_data = {.Size_32, .Size_16}
                case "as64":  cst_addr = {.Size_64}
                case "as32":  cst_addr = {.Size_32}
                case "as16":  cst_addr = {.Size_16}
                case "vexw1": vexw = 0b10
                case "vexw0": vexw = 0b01
                case "mod11": cst_mod = {.Mod_11}
                case "moda":  cst_mod = {.Mod_00,.Mod_01,.Mod_10}
                case "modb":  cst_mod = {.Mod_00,.Mod_11}
                case "modab": cst_mod = {.Mod_00}
                case:
                    fmt.eprintf("Error(%d): Unknown constraint: %s\n", line_no, c)
                    os.exit(1)
            }
        } else {
            fmt.eprintf("Error(%d): Unknown instruction flag: %s\n", line_no, e)
            os.exit(1)
        }
    }
    rxt: Reg_Set
    if rx_kind != nil {
        rxt = rx_kind.?
    } else {
        rxt = .Reg
    }
    rmt: Reg_Set
    if rm_kind != nil {
        rmt = rm_kind.?
    } else {
        rmt = rxt
    }
    cst_line := make_cst_line(vexw, mod_kind, cst_mod, cst_cpu, cst_data, cst_addr)
    flg_line := make_flg_line(data_size, flags, eop)
    encodings: [dynamic]Encoding_Line
    if dp_prefix == nil {
        data_prefixes := .Rep in flags? []Data_Prefix{.Prefix_Np, .Prefix_66, .Prefix_F2, .Prefix_F3} : []Data_Prefix{.Prefix_Np, .Prefix_66}
        for dp in data_prefixes {
            if rx_loop {
                for ri in u8(0) ..< 8 {
                    pfx_line := make_pfx_line(vex, dp, op_prefix)
                    rmx_line := make_rmx_line(rmm, rmt, rxt, rm_size, rx_size, ri)
                    enc := Encoding_Line {
                        mnemonic = mnemonic,
                        cst_line = cst_line,
                        pfx_line = pfx_line,
                        rmx_line = rmx_line,
                        flg_line = flg_line,
                        line_no  = cast(u64) line_no,
                        opcode   = opcode_u8+ri,
                        opcode_rx = opcode_rx,
                    }
                    append(&encodings, enc)
                }
            } else {
                pfx_line := make_pfx_line(vex, dp, op_prefix)
                rmx_line := make_rmx_line(rmm, rmt, rxt, rm_size, rx_size, rx_index)
                enc := Encoding_Line {
                    mnemonic = mnemonic,
                    cst_line = cst_line,
                    pfx_line = pfx_line,
                    rmx_line = rmx_line,
                    flg_line = flg_line,
                    line_no  = cast(u64) line_no,
                    opcode   = opcode_u8,
                    opcode_rx = opcode_rx,
                }
                append(&encodings, enc)
            }
        }
    } else {
        pfx_line := make_pfx_line(vex, dp_prefix.?, op_prefix)
        rmx_line := make_rmx_line(rmm, rmt, rxt, rm_size, rx_size, rx_index)
        enc := Encoding_Line {
            mnemonic = mnemonic,
            cst_line = cst_line,
            pfx_line = pfx_line,
            rmx_line = rmx_line,
            flg_line = flg_line,
            line_no  = cast(u64) line_no,
            opcode   = opcode_u8,
            opcode_rx = opcode_rx,
        }
        append(&encodings, enc)
    }
    return encodings[:]
}

encoding_is_duplicate :: proc(enc1: Encoding_Line, enc2: Encoding_Line) -> bool {
    if enc1.pfx_line != enc2.pfx_line {
        return false
    }
    if enc1.opcode != enc2.opcode {
        return false
    }
    if cst_mask(enc1.cst_line) ~ cst_mask(enc2.cst_line) != 0 {
        return false
    }
    mk1 := cst_mod_kind(enc1.cst_line)
    mk2 := cst_mod_kind(enc2.cst_line)
    switch mk1 {
        case .None:
            return true
        case .Normal:
            return true
        case .Opcode_Ext:
            if mk2 == .Opcode_Ext || mk2 == .Opcode {
                return enc1.opcode_rx == enc2.opcode_rx
            }
        case .Opcode:
            if mk2 == .Opcode_Ext {
                return enc1.opcode_rx == enc2.opcode_rx
            } else if mk2 == .Opcode {
                rm1 := rmx_rm(enc1.rmx_line)
                rm2 := rmx_rm(enc2.rmx_line)
                return enc1.opcode_rx == enc2.opcode_rx && rm1 == rm2
            }
    }
    return true
}

Table_Contents :: struct {
    encoding_cohorts: [][][dynamic]Encoding_Ext,
    encodings:        [][]Encoding,
    slice_table:      [dynamic][]Encoding,
    rx_ext_table:     [dynamic][8]Encoding,
    string_table:     [dynamic]string,
    string_index_map: map[string]u16,
}

table_init :: proc() -> Table_Contents {
    table := make([][][dynamic]Encoding_Ext, 32)
    for _, prefix_line in table {
        table[prefix_line] = make([][dynamic]Encoding_Ext, 256)
        for _, opcode in table[prefix_line] {
            table[prefix_line][opcode] = make([dynamic]Encoding_Ext)
        }
    }
    encodings := make([][]Encoding, 32)
    for _, prefix_line in encodings {
        encodings[prefix_line] = make([]Encoding, 256)
    }
    tc := Table_Contents {
        encoding_cohorts = table,
        encodings = encodings,
        slice_table = make([dynamic][]Encoding),
        rx_ext_table = make([dynamic][8]Encoding),
        string_table = make([dynamic]string),
        string_index_map = make(map[string]u16),
    }
    append(&tc.string_table, "")
    append(&tc.slice_table, make([]Encoding, 0))
    append(&tc.rx_ext_table, [8]Encoding{})
    return tc
}

table_get_strtab_idx :: proc(tc: ^Table_Contents, s: string) -> u16 {
    if s in tc.string_index_map {
        return tc.string_index_map[s]
    } else {
        new_idx := cast(u16) len(tc.string_table)
        tc.string_index_map[s] = new_idx
        append(&tc.string_table, s)
        return new_idx
    }
}

encoding_from_line :: proc(tc: ^Table_Contents, encoding: Encoding_Line) -> Encoding_Ext {
    strtab_idx := table_get_strtab_idx(tc, encoding.mnemonic)
    assert(strtab_idx > 0)
    return Encoding_Ext {
        mnemonic = strtab_idx,
        cst_line = encoding.cst_line,
        flg_line = encoding.flg_line,
        rmx_line = encoding.rmx_line,
        rx_ext = encoding.opcode_rx,
    }
}

table_write_encoding :: proc(tc: ^Table_Contents, encoding: Encoding_Line) {
    append(&tc.encoding_cohorts[encoding.pfx_line][encoding.opcode], encoding_from_line(tc, encoding))
}

table_process_cohort :: proc(tc: ^Table_Contents, prefix_line: u8, opcode: u8, cohort: []Encoding_Ext) {
    if len(cohort) == 0 {
        return
    }
    assert(cohort[0].mnemonic != 0)
    mod_kind := cst_mod_kind(cohort[0].cst_line)
    if mod_kind == .None || mod_kind == .Normal {
        if len(cohort) == 1 {
            tc.encodings[prefix_line][opcode] = cohort[0]
        } else {
            slice_idx := len(tc.slice_table)
            assert(slice_idx > 0)
            append(&tc.slice_table, make([]Encoding, len(cohort)))
            for e, e_idx in cohort {
                tc.slice_table[slice_idx][e_idx] = e
            }
            tc.encodings[prefix_line][opcode] = Encoding {
                cst_line = cohort[0].cst_line, // mod kind either some or none
                mnemonic = cast(u16) slice_idx,
                flg_line = flg_set(cohort[0].flg_line, .Is_Slice),
                rmx_line = 0,
            }
        }
    } else {
        for e in cohort {
            mk := cst_mod_kind(e.cst_line)
            if ! (mk == .Opcode || mk == .Opcode_Ext) {
                fmt.eprintf("Prefix %#05b, Opcode %#02x: Non-mod/rm encodings in a cohort")
                os.exit(1)
            }
        }
        rx_cohorts := [8][dynamic]Encoding {}
        rx_slices := [8]Encoding {}
        for e in cohort {
            append(&rx_cohorts[e.rx_ext], e)
        }
        for co, rx in rx_cohorts {
            if len(co) == 0 {
                continue
            }
            slice_idx := len(tc.slice_table)
            assert(slice_idx > 0)
            append(&tc.slice_table, make([]Encoding, len(co)))
            for e, e_idx in co {
                tc.slice_table[slice_idx][e_idx] = e
            }
            rx_slices[rx] = Encoding {
                cst_line = co[0].cst_line,
                mnemonic = cast(u16) slice_idx,
                rmx_line = 0,
                flg_line = flg_set(co[0].flg_line, .Is_Slice),
            }
        }
        rx_ext_idx := len(tc.rx_ext_table)
        append(&tc.rx_ext_table, [8]Encoding{})
        for rx in 0 ..< 8 {
            tc.rx_ext_table[rx_ext_idx][rx] = rx_slices[rx]
        }
        tc.encodings[prefix_line][opcode] = Encoding {
            cst_line = cohort[0].cst_line,
            mnemonic = cast(u16) rx_ext_idx,
            flg_line = flg_set(cohort[0].flg_line, .Rx_Ext),
            rmx_line = 0,
        }
    }
}

write_tables_to_dst :: proc(tc: ^Table_Contents) {
    file, ok := os.open(DST_PATH, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
    if ok != {} {
        fmt.eprintf("Error opening file for writing: %s", DST_PATH)
    }
    fmt.fprintf(file, "package %s\n\n", PACKAGE_NAME)
    fmt.fprintf(file, "// This file is AUTO-GENERATED by disasm/table_gen from %s\n\n", SRC_PATH)
    fmt.fprintf(file, "encodings := [][]u64 {{\n")
    for pfx_line in 0 ..< 32 {
        fmt.fprintf(file, IND1+"prefix_table_%02d,\n", pfx_line)
    }
    fmt.fprintf(file, "}}\n\n")
    for pfx_group, pfx_line in tc.encodings {
        fmt.fprintf(file, "@(private)\nprefix_table_%02d := []u64 {{\n", pfx_line)
        for op_group, opcode in pfx_group {
            fmt.fprintf(file, IND1+"%#.02x = %#.16x,\n", opcode, transmute(u64) op_group)
        }
        fmt.fprintf(file, "}}\n\n")
    }
    fmt.fprintf(file, "string_table := []string {{\n")
    for s, idx in tc.string_table {
        fmt.fprintf(file, IND1+`%#.04x = "%s",`+"\n", idx, s)
    }
    fmt.fprintf(file, "}}\n\n")
    fmt.fprintf(file, "rx_ext_table := [][8]u64 {{\n")
    for rx_ext, rx_idx in tc.rx_ext_table {
        fmt.fprintf(file, IND1+"%#.04x = [8]u64 {{\n", rx_idx)
        for rx in 0 ..< 8 {
            fmt.fprintf(file, IND2+"%d = %#.016x,\n", rx, transmute(u64) rx_ext[rx])
        }
        fmt.fprintf(file, IND1+"}},\n")
    }
    fmt.fprintf(file, "}}\n\n")
    fmt.fprintf(file, "slice_table := [][]u64 {{\n")
    for slc, slc_idx in tc.slice_table {
        fmt.fprintf(file, IND1+"%#.04x = []u64 {{\n", slc_idx)
        for enc, enc_idx in slc {
            fmt.fprintf(file, IND2+"%d = %#.016x,\n", enc_idx, transmute(u64) enc)
        }
        fmt.fprintf(file, IND1+"}},\n")
    }
    fmt.fprintf(file, "}}\n\n")
    os.close(file)
}

main :: proc() {
    src_table, src_table_ok := os.read_entire_file(SRC_PATH)
    if !src_table_ok {
        fmt.eprintf("Error: File %s wasn't found\n", SRC_PATH)
        os.exit(1)
    }
    line_no := 1
    encoding_list := make([dynamic]Encoding_Line)
    for line in strings.split_by_byte_iterator(cast(^string) &src_table, '\n') {
        if len(line) == 0 || line[0] == '#' {
            line_no += 1
            continue
        }
        encodings := parse_line(line_no, line)
        for encoding in encodings {
            append(&encoding_list, encoding)
        }
        line_no += 1
    }
    for enc1, idx1 in encoding_list {
        for enc2 in encoding_list[:idx1] {
            if encoding_is_duplicate(enc1, enc2) {
                fmt.eprintf("Error(%d): Encoding for %v has the same encoding as %v (line %d)\n",
                    enc1.line_no, enc1.mnemonic,
                    enc2.mnemonic, enc2.line_no,
                )
                fmt.printf("%v\n%v\n", enc1, enc2)
                os.exit(1)
            }
        }
    }
    table := table_init()
    for enc in encoding_list {
        table_write_encoding(&table, enc)
    }
    for _, prefix in table.encoding_cohorts {
        for cohort, opcode in table.encoding_cohorts[prefix] {
            table_process_cohort(&table, auto_cast prefix, auto_cast opcode, cohort[:])
        }
    }
    write_tables_to_dst(&table)
}
