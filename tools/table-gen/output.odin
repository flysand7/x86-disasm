package tablegen

import "core:os"
import "core:strings"
import "core:fmt"
import "core:unicode"

import "lib:table"

TAB  :: "    "
PACKAGE :: "x86_disasm"

Stage1_Encoding :: struct {
    kind: table.Encoding_Kind,
    entry_idx: int,
    eop: table.EOP_Kind,
    force_ds: u8,
}

Encoding :: struct {
    mnemonic: string,
    flags: bit_set[table.Flag],
    rx_value: u8,
    rx_kind: table.RX_Kind,
    rm_kind: table.RM_Kind,
}

capitalize_mnemonic :: proc(mnemonic: string) -> string {
    first := [1]u8 {}
    if 'a' <= mnemonic[0] && mnemonic[0] <= 'z' {
        first[0] = mnemonic[0] - 'a' + 'A'
    }
    return strings.concatenate(
        []string {
            transmute(string) first[:],
            mnemonic[1:]
        }
    )
}

output_tables :: proc(entries: []table.Entry, filename: string) -> (bool) {
    builder: strings.Builder = ---
    mnemonic_counter := 0
    mnemonic_table := make(map[string]int)
    stage1_encodings := make([]Stage1_Encoding, 0x100)
    rx_extensions := make([dynamic][8]int, 1)
    stage2_encodings := make([dynamic]Encoding, 1)
    strings.builder_init(&builder)
    for entry in entries {
        if entry.mnemonic not_in mnemonic_table {
            mnemonic_table[entry.mnemonic] = mnemonic_counter
            mnemonic_counter += 1
        }
        mnemonic_idx := mnemonic_table[entry.mnemonic]
        stage1_idx := -1
        stage2_idx := -1
        rx_ext_idx := -1
        if entry.encoding_kind == .Rx_Extend {
            if stage1_encodings[entry.opcode].entry_idx == 0 {
                stage1_encodings[entry.opcode] = Stage1_Encoding {
                    entry_idx = len(rx_extensions),
                    eop = entry.eop,
                    kind = entry.encoding_kind,
                    force_ds = entry.force_ds,
                }
                append(&rx_extensions, [8]int {})
            }
            stage1 := stage1_encodings[entry.opcode]
            exts := &rx_extensions[stage1.entry_idx]
            exts[entry.rx_value] = len(stage2_encodings)
            rx_ext_idx = len(rx_extensions) - 1
        } else {
            stage1_encodings[entry.opcode] = Stage1_Encoding {
                entry_idx = len(stage2_encodings),
                eop = entry.eop,
                kind = entry.encoding_kind,
                force_ds = entry.force_ds,
            }
        }
        stage1_idx = int(entry.opcode)
        append(&stage2_encodings, Encoding {
            mnemonic = entry.mnemonic,
            flags = entry.flags,
            rm_kind = entry.rm_kind,
            rx_kind = entry.rx_kind,
            rx_value = entry.rx_value,
        })
        stage2_idx = len(stage2_encodings) - 1
        if do_print_table {
            line_matches := print_line == -1 || entry.src_line == print_line
            mnemonic_matches := print_mnemonic == "" || entry.mnemonic == print_mnemonic
            opcode_matches := print_opcode == -1 || entry.opcode == u8(print_opcode)
            if line_matches && mnemonic_matches && opcode_matches {
                table.print_entry(entry)
                if stage1_idx != -1 {
                    fmt.printfln("+-> Stage1 [%#.2x] = %v", stage1_idx, stage1_encodings[stage1_idx])
                }
                if rx_ext_idx != -1 {
                    fmt.printfln("+-> RX Ext: [%d] = %v", rx_ext_idx, rx_extensions[rx_ext_idx])
                }
                if stage2_idx != -1 {
                    fmt.printfln("+-> Stage2: [%d] = %v", stage1_idx, stage2_encodings[stage2_idx])
                }
            }
        }
    }
    fmt.sbprintfln(&builder, "package %s", PACKAGE)
    fmt.sbprintfln(&builder, "when !X86_USE_STUB {{")
    fmt.sbprintln(&builder)
    // Print mnemonics
    fmt.sbprintfln(&builder, "Mnemonic :: enum {{")
    for mnemonic, k in mnemonic_table {
        fmt.sbprintfln(&builder, TAB+"%s,", capitalize_mnemonic(mnemonic))
    }
    fmt.sbprintfln(&builder, "}}")
    fmt.sbprintln(&builder)
    // Print mnemonic table
    fmt.sbprintfln(&builder, "mnemonic_table := [Mnemonic]string {{")
    for mnemonic,k in mnemonic_table {
        fmt.sbprintfln(&builder, TAB+".%s = \"%s\",", capitalize_mnemonic(mnemonic), mnemonic)
    }
    fmt.sbprintfln(&builder, "}}")
    fmt.sbprintln(&builder)
    // Print stage 1
    fmt.sbprintfln(&builder, "stage1_table := [?]Stage1_Encoding {{")
    for entry, opcode in stage1_encodings {
        if entry.entry_idx != 0 {
            fmt.sbprintfln(&builder, TAB+"%#.2x = {{", opcode)
            fmt.sbprintfln(&builder, TAB+TAB+"entry_idx = %d,", entry.entry_idx)
            fmt.sbprintfln(&builder, TAB+TAB+"eop = .%v,", entry.eop)
            fmt.sbprintfln(&builder, TAB+TAB+"kind = .%v,", entry.kind)
            fmt.sbprintfln(&builder, TAB+TAB+"force_ds = %#.2x,", entry.force_ds)
            fmt.sbprintfln(&builder, TAB+"}},")
        }
    }
    fmt.sbprintfln(&builder, "}}")
    fmt.sbprintln(&builder)
    // Print rx extensions
    fmt.sbprintfln(&builder, "rx_ext_table := [?][8]int {{")
    fmt.sbprintfln(&builder, TAB+"0 = {{}},")
    for rx_ext, idx in rx_extensions[1:] {
        idx := idx + 1
        fmt.sbprintf(&builder, TAB+"%d = {{", idx)
        for stage2_idx in rx_ext {
            fmt.sbprintf(&builder, "%d,", stage2_idx)
        }
        fmt.sbprintfln(&builder, "}},")
    }
    fmt.sbprintfln(&builder, "}}")
    fmt.sbprintln(&builder)
    // Print stage2
    fmt.sbprintfln(&builder, "stage2_table := [?]Encoding {{")
    fmt.sbprintfln(&builder, TAB+"0 = {{}},")
    for entry, idx in stage2_encodings[1:] {
        idx := idx + 1
        fmt.sbprintfln(&builder, TAB+"%d = {{", idx)
        fmt.sbprintfln(&builder, TAB+TAB+"mnemonic = .%s,", capitalize_mnemonic(entry.mnemonic))
        fmt.sbprintf(&builder, TAB+TAB+"flags = {{")
        if .D in entry.flags {
            fmt.sbprintf(&builder, ".D,")
        }
        fmt.sbprintfln(&builder, "}},")
        fmt.sbprintfln(&builder, TAB+TAB+"rm_kind = .%v,", entry.rm_kind)
        fmt.sbprintfln(&builder, TAB+TAB+"rx_kind = .%v,", entry.rx_kind)
        fmt.sbprintfln(&builder, TAB+TAB+"rx_value = %#.2x,", entry.rx_value)
        fmt.sbprintfln(&builder, TAB+"}},")
    }
    fmt.sbprintfln(&builder, "}}")
    fmt.sbprintln(&builder)
    // Done
    fmt.sbprintfln(&builder, "}}")
    os.write_entire_file(filename, transmute([]u8) strings.to_string(builder), true) or_return
    return true
}



