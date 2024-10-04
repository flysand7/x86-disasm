package table


Stage1_Encoding :: struct {
    kind: Encoding_Kind,
    entry_idx: int,
    eop: EOP_Kind,
    force_ds: u8,
}

Encoding :: struct {
    mnemonic: string,
    flags: Flags,
    rx_value: u8,
    rx_kind: RX_Kind,
    rm_kind: RM_Kind,
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

mt_add :: proc(mt: ^Multistage_Tables, entry: Entry) {
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
        assert(stage1.entry_idx == 0, "Attempt to write two encodings to the same first stage")
        stage1.entry_idx = stage2_idx
    }
}

