package tablegen

import "core:os"
import "core:strings"
import "core:fmt"
import "core:unicode"

import "disasm:table"

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

Multistage_Tables :: struct {
    mnemonic_counter: int,
    mnemonic_table: map[string]int,
    s1_table: []Stage1_Encoding,
    rx_table: [dynamic][8]int,
    s2_table: [dynamic]Encoding,
}

mt_init :: proc(mt: ^Multistage_Tables) {
    mt.mnemonic_counter = 0
    mt.mnemonic_table = make(map[string]int)
    mt.s1_table = make([]Stage1_Encoding, 0x100)
    mt.rx_table = make([dynamic][8]int, 1)
    mt.s2_table = make([dynamic]Encoding, 1)
}

mt_mnemonic :: proc(mt: ^Multistage_Tables, mnemonic: string) -> int {
    if mnemonic not_in mt.mnemonic_table {
        mt.mnemonic_table[mnemonic] = mt.mnemonic_counter
        mt.mnemonic_counter += 1
    }
    return mt.mnemonic_table[mnemonic]
}

mt_add_s1 :: proc(mt: ^Multistage_Tables, opcode: u8) -> ^Stage1_Encoding {
    return &mt.s1_table[opcode]
}

s1_present :: proc(s1: ^Stage1_Encoding) -> bool {
    return s1.entry_idx != 0
}

mt_add_s2 :: proc(mt: ^Multistage_Tables) -> (^Encoding, int) {
    idx := len(mt.s2_table)
    append(&mt.s2_table, Encoding {})
    return &mt.s2_table[idx], idx
}

mt_add_rx_ext :: proc(mt: ^Multistage_Tables) -> ([]int, int) {
    idx := len(mt.rx_table)
    append(&mt.rx_table, [8]int {})
    return mt.rx_table[idx][:], idx
}

mt_add :: proc(mt: ^Multistage_Tables, entry: table.Entry) {
    mnemonic_idx := mt_mnemonic(mt, entry.mnemonic)
    // Second stage comes first, since everything points into it
    stage2, stage2_idx := mt_add_s2(mt)
    stage2.flags = entry.flags
    stage2.mnemonic = entry.mnemonic
    stage2.rm_kind = entry.rm_kind
    stage2.rx_kind = entry.rx_kind
    stage2.rx_value = entry.rx_value
    // Create the first stage, if it doesn't exist
    stage1 := mt_add_s1(mt, entry.opcode)
    if !s1_present(stage1) {
        stage1.eop = entry.eop
        stage1.force_ds = entry.force_ds
        stage1.kind = entry.encoding_kind
    }
    // If opcode has an rx extension, the intermediate table entry is generated
    // in the rx extensions table, otherwise stage1 connects to stage2 normally.
    if stage1.kind == .Rx_Extend {
        rx_exts: []int
        rx_exts_idx: int
        if stage1.entry_idx == 0 {
            rx_exts, rx_exts_idx = mt_add_rx_ext(mt)
            stage1.entry_idx = rx_exts_idx
        } else {
            rx_exts_idx = stage1.entry_idx
            rx_exts = mt.rx_table[rx_exts_idx][:]
        }
        assert(rx_exts[entry.rx_value] == 0, "Attempt to put 2 entires int he same table")
        rx_exts[entry.rx_value] = stage2_idx
    } else {
        stage1.entry_idx = stage2_idx
    }
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
    strings.builder_init(&builder)
    mt: Multistage_Tables = ---
    mt_init(&mt)
    for entry in entries {
        mt_add(&mt, entry)
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
