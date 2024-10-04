#+private
package table

import "core:fmt"
import "core:strings"

Marked_Entry :: struct {
    line_no: int,
    mnemonic: string,
    opcode: string,
    encoding_kind: Encoding_Kind,
    opcode_rx: bool,
    rx_spec: string,
    eop: string,
    flags: map[string]string,
}

mark_fields :: proc(line_no: int, fields: []string) -> (Marked_Entry, bool) {
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
    entry := Marked_Entry {
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
