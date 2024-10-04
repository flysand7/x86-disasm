package tablegen

import "core:os"
import "core:strings"
import "core:fmt"
import "core:unicode"

import "disasm:table"

TAB  :: "    "
PACKAGE :: "x86_disasm"

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
    strings.builder_init(&builder)
    mt: table.Multistage_Tables = ---
    table.mt_init(&mt)
    for entry in entries {
        table.mt_add(&mt, entry)
    }
    fmt.sbprintfln(&builder, "package %s", PACKAGE)
    fmt.sbprintfln(&builder, "when !X86_USE_STUB {{")
    fmt.sbprintln(&builder)
    // Print mnemonics
    fmt.sbprintfln(&builder, "Mnemonic :: enum {{")
    for mnemonic, k in mt.mnemonic_table {
        fmt.sbprintfln(&builder, TAB+"%s,", capitalize_mnemonic(mnemonic))
    }
    fmt.sbprintfln(&builder, "}}")
    fmt.sbprintln(&builder)
    // Print mnemonic table
    fmt.sbprintfln(&builder, "mnemonic_table := [Mnemonic]string {{")
    for mnemonic,k in mt.mnemonic_table {
        fmt.sbprintfln(&builder, TAB+".%s = \"%s\",", capitalize_mnemonic(mnemonic), mnemonic)
    }
    fmt.sbprintfln(&builder, "}}")
    fmt.sbprintln(&builder)
    // Print stage 1
    fmt.sbprintfln(&builder, "stage1_table := [?]Stage1_Encoding {{")
    for entry, opcode in mt.s1_table {
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
    for rx_ext, idx in mt.rx_table[1:] {
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
    for entry, idx in mt.s2_table[1:] {
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
