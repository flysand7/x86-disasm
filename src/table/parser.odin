package table

import "core:strings"
import "core:strconv"
import "core:fmt"
import "core:os"

@(private)
is_oct_digit :: proc(d: u8) -> bool {
    return '0' <= d && d <= '7'
}

@(private)
is_digit :: proc(d: u8) -> bool {
    return '0' <= d && d <= '9'
}

@(private)
from_digit :: proc(d: u8) -> u8 {
    return d - '0'
}

@(private)
parse_byte :: proc(line_no: int, byte_str: string) -> (u8, bool) {
    if len(byte_str) != 2 {
        fmt.eprintfln("Line %d: Byte needs to be 2 characters in length (%s)", line_no, byte_str)
        return 0, false
    }
    hi := u8(0)
    lo := u8(0)
    switch byte_str[0] {
    case 'a'..='f': hi = byte_str[0] - 'a' + 10
    case '0'..='9': hi = byte_str[0] - '0'
    case:
        fmt.eprintfln("Line %d: Unexpected hex digit in a byte (%s)", line_no, byte_str)
        return 0, false
    }
    switch byte_str[1] {
    case 'a'..='f': lo = byte_str[1] - 'a' + 10
    case '0'..='9': lo = byte_str[1] - '0'
    case:
        fmt.eprintfln("Line %d: Unexpected hex digit in a byte (%s)", line_no, byte_str)
        return 0, false
    }
    return hi<<4 | lo, true
}

@(private)
parse_int :: proc(line_no: int, value: string) -> (u8, bool) {
    value, ok := strconv.parse_int(value)
    if !ok {
        fmt.eprintfln("Line %d: Bad number (%s)", line_no, value)
        return 0, false
    }
    if !(0 <= value && value <= 0xff) {
        fmt.eprintfln("Line %d: Byte value overflow (%s)", line_no, value)
        return 0, false
    }
    return u8(value), true
}

@(private)
parse_rx_kind :: proc(line_no: int, rx_spec: string) -> (RX_Kind, u8, bool) {
    idx := 0
    for b in transmute([]byte) rx_spec {
        if is_digit(b) {
            break
        }
        idx += 1
    }
    rx_kind_str := rx_spec[0:idx]
    rx_value_str := rx_spec[idx:]
    rx_kind: RX_Kind
    switch rx_kind_str {
    case "":  rx_kind = .None
    case "gr": rx_kind = .GPReg
    case "sr": rx_kind = .SReg
    case:
        fmt.eprintfln("Line %d: Unknown RX register kind (%s)", line_no, rx_kind_str)
        return .None, REG_NONE, false
    }
    rx_value := REG_NONE
    if len(rx_value_str) > 0 {
        if len(rx_value_str) != 1 {
            fmt.eprintfln("Line %d: RX register index must be one digit (%s)", line_no, rx_value_str)
            return rx_kind, REG_NONE, false
        }
        rx_value = from_digit(rx_value_str[0])
    }
    return rx_kind, rx_value, true
}

@(private)
parse_rm_kind :: proc(line_no: int, rm_kind: string) -> (RM_Kind, bool) {
    switch rm_kind {
    case "": return .None, true
    case "gr": return .GPReg, true
    }
    fmt.eprintfln("Line %d: Unknown RM register kind (%s)", line_no, rm_kind)
    return .None, false
}

@(private)
rm_to_rx :: proc(line_no: int, rm_kind: RM_Kind) -> (RX_Kind, bool) {
    switch rm_kind {
    case .None: panic("Unknown RM register kind")
    case .GPReg: return .GPReg, true
    }
    unreachable()
}

@(private)
parse_eop_kind :: proc(line_no: int, eop_kind: string) -> (EOP_Kind, bool) {
    switch eop_kind {
    case "": return .None, true
    case "imm": return .Imm, true
    case "imm8": return .Imm8, true
    case "disp": return .Disp, true
    case "saddr": return .SAddr, true
    case "faddr": return .FAddr, true
    case "naddr": return .NAddr, true
    }
    fmt.eprintfln("Line %d: Unknown extra operand kind (%s)", line_no, eop_kind)
    return .None, false
}

@(private)
Entry_Fields :: struct {
    line_no: int,
    mnemonic: string,
    opcode: string,
    encoding_kind: Encoding_Kind,
    opcode_rx: bool,
    rx_spec: string,
    eop: string,
    flags: map[string]string,
}

@(private)
parse_entry_fields :: proc(line_no: int, fields: []string) -> (Entry_Fields, bool) {
    // Parse mnemonic
    idx := 0
    if idx >= len(fields) {
        fmt.eprintfln("Line %d: Expected mnemonic", line_no)
        return {}, false
    }
    mnemonic := fields[idx]
    idx += 1
    // Parse opcode byte
    opcode := fields[idx]
    encoding_kind := Encoding_Kind.None
    opcode_rx := false
    if opcode[len(opcode)-1] == '+' {
        opcode_rx = true
        opcode = opcode[0:len(opcode)-1]
        encoding_kind = .Rx_Embed
    }
    rx_spec := ""
    opcode_slash := strings.index_byte(opcode, '/')
    if opcode_slash != -1 {
        rx_spec = opcode[opcode_slash+1:]
        opcode = opcode[0:opcode_slash]
        if encoding_kind != .None {
            fmt.eprintfln("Line %d: Cannot specify RX extend and RX embed in the same opcode", line_no)
            return {}, false
        }
        if len(rx_spec) != 1 {
            fmt.eprintfln("Line %d: Opcode RX needs to be one character in length", line_no)
            return {}, false
        }
        if !is_oct_digit(rx_spec[0]) {
            fmt.eprintfln("Line %d: Opcode RX needs to be an octal digit", line_no)
            return {}, false
        }
        encoding_kind = .Rx_Extend
    }
    idx += 1
    // Parse mod/rm specification
    if idx < len(fields) && fields[idx][0] == '/' {
        rx_spec = fields[idx][1:]
        if encoding_kind != .None {
            fmt.eprintfln("Line %d: Conflicting mod/rm behaviors", line_no)
            return {}, false
        }
        if len(rx_spec) == 0 {
            fmt.eprintfln("Line %d: Expected register type or digit after mod/rm specification", line_no)
            return {}, false
        }
        if len(rx_spec) == 1 && is_oct_digit(rx_spec[0]) {
            fmt.eprintfln("Line %d: Opcode RX needs to be adjacent to opcode", line_no)
            return {}, false
        }
        encoding_kind = .Mod_Rm
        idx += 1
    }
    // Parse extra operand
    eop := ""
    if idx < len(fields) && fields[idx][0] != '+' {
        eop = fields[idx]
        idx += 1
    }
    // Parse flags
    flags := make(map[string]string)
    for field in fields[idx:] {
        if field[0] != '+' {
            fmt.eprintfln("Line %d: Flags are expected to start with '+' (%s is not a valid flag)", line_no, field)
            return {}, false
        }
        eq_pos := strings.index_byte(field, '=')
        if eq_pos != -1 {
            name := field[1:eq_pos]
            value := field[eq_pos+1:]
            if len(name) == 0 {
                fmt.eprintfln("Line %d: Flags must have a name (%s)", line_no, field)
                return {}, false
            }
            if len(value) == 0 {
                fmt.eprintfln("Line %d: Expected flag value (%s)", line_no, field)
                return {}, false
            }
            flags[name] = value
        } else {
            name := field[1:]
            if len(name) == 0 {
                fmt.eprintfln("Line %d: Flags must have a name (%s)", line_no, field)
                return {}, false
            }
            flags[name] = name
        }
    }
    entry := Entry_Fields {
        line_no = line_no,
        mnemonic = mnemonic,
        opcode = opcode,
        opcode_rx = opcode_rx,
        encoding_kind = encoding_kind,
        rx_spec = rx_spec,
        eop = eop,
        flags = flags,
    }
    return entry, true
}

@(private)
entries_from_fields :: proc(m: Entry_Fields) -> (entries: [dynamic]Entry, ok: bool) {
    rx_kind := RX_Kind.None
    rm_kind := RM_Kind.None
    rx_value := REG_NONE
    if m.rx_spec != "" {
        if len(m.rx_spec) == 1 && is_digit(m.rx_spec[0]) {
            rx_value = from_digit(m.rx_spec[0])
        } else {
            rx_kind, rx_value = parse_rx_kind(m.line_no, m.rx_spec) or_return
        }
    }
    flags := Flags {}
    ds := DS_DEFAULT
    for flag, value in m.flags {
        switch flag {
        case "d": flags += {.D}
        case "rx":
            rx_kind, rx_value = parse_rx_kind(m.line_no, value) or_return
        case "rm": rm_kind = parse_rm_kind(m.line_no, value) or_return
        case "ds": ds = (parse_int(m.line_no, value) or_return)/8
        }
    }
    if rm_kind == RM_Kind.None && m.encoding_kind != .None {
        rm_kind = .GPReg
    }
    if rx_kind == RX_Kind.None && m.encoding_kind != .Rx_Extend && m.encoding_kind != .None {
        rx_kind = rm_to_rx(m.line_no, rm_kind) or_return
    }
    eop_kind := parse_eop_kind(m.line_no, m.eop) or_return
    start_opcode := parse_byte(m.line_no, m.opcode) or_return
    end_opcode := start_opcode + (7 if m.opcode_rx else 0)
    for opcode in start_opcode ..= end_opcode {
        rx_value = opcode - start_opcode if m.opcode_rx else rx_value
        entry := Entry {
            src_line = m.line_no,
            mnemonic = m.mnemonic,
            opcode = opcode,
            encoding_kind = m.encoding_kind,
            eop = eop_kind,
            rx_value = rx_value,
            rx_kind = rx_kind,
            rm_kind = rm_kind,
            force_ds = ds,
            flags = flags,
        }
        append(&entries, entry)
    }
    return entries, true
}

parse :: proc(table: string) -> []Entry {
    table := table
    line_no := 0
    entries := make([dynamic]Entry)
    for line in strings.split_lines_iterator(&table) {
        defer line_no += 1
        line := strings.trim(line, " ")
        if len(line) == 0 || line[0] == '#' {
            continue
        }
        marked_entry, m_ok := parse_entry_fields(line_no, strings.fields(line))
        if !m_ok {
            os.exit(1)
        }
        table_entries, t_ok := entries_from_fields(marked_entry)
        if !t_ok {
            os.exit(1)
        }
        append_elems(&entries, ..table_entries[:])
    }
    return entries[:]
}
