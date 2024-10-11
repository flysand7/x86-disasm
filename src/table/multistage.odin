package table

Stage1_Encoding :: struct {
    mnemonic: string,
    kind: Encoding_Kind,
    entry_idx: int,
    eop: EOP_Kind,
    force_ds: u8,
}

RX_Ext_Encoding :: struct {
    mnemonic: string,
    entry_idx: int,
}

Stage2_Encoding :: struct {
    flags: bit_set[Flag],
    rx_value: u8,
    rx_kind: RX_Kind,
    rm_kind: RM_Kind,
}

Multistage_Tables :: struct {
    mnemonic_counter: int,
    mnemonic_table: map[string]int,
    s1_table: []Stage1_Encoding,
    rx_table: [dynamic][8]RX_Ext_Encoding,
    s2_table: [dynamic]Stage2_Encoding,
}

mt_init :: proc(mt: ^Multistage_Tables) {
    mt.mnemonic_counter = 0
    mt.mnemonic_table = make(map[string]int)
    mt.s1_table = make([]Stage1_Encoding, 0x100)
    mt.rx_table = make([dynamic][8]RX_Ext_Encoding, 1)
    mt.s2_table = make([dynamic]Stage2_Encoding, 1)
}

mt_mnemonic :: proc(mt: ^Multistage_Tables, mnemonic: string) -> int {
    if mnemonic not_in mt.mnemonic_table {
        mt.mnemonic_table[mnemonic] = mt.mnemonic_counter
        mt.mnemonic_counter += 1
    }
    return mt.mnemonic_table[mnemonic]
}

@(private="file")
mt_add_s1 :: proc(mt: ^Multistage_Tables, opcode: u8) -> ^Stage1_Encoding {
    return &mt.s1_table[opcode]
}

@(private="file")
s1_present :: proc(s1: ^Stage1_Encoding) -> bool {
    return s1.entry_idx != 0
}

@(private="file")
mt_ensure_s2 :: proc(mt: ^Multistage_Tables, entry: Entry) -> (^Stage2_Encoding, int) {
    find_encoding := Stage2_Encoding {
        flags = entry.flags,
        rm_kind = entry.rm_kind,
        rx_kind = entry.rx_kind,
        rx_value = entry.rx_value,
    }
    for &e, i in mt.s2_table[1:] {
        if e == find_encoding {
            return &e, i+1
        }
    }
    idx := len(mt.s2_table)
    append(&mt.s2_table, Stage2_Encoding {})
    mt.s2_table[idx] = find_encoding
    return &mt.s2_table[idx], idx
}

@(private="file")
mt_add_rx_ext :: proc(mt: ^Multistage_Tables) -> ([]RX_Ext_Encoding, int) {
    idx := len(mt.rx_table)
    append(&mt.rx_table, [8]RX_Ext_Encoding {})
    return mt.rx_table[idx][:], idx
}

mt_add :: proc(mt: ^Multistage_Tables, entry: Entry) {
    mnemonic_idx := mt_mnemonic(mt, entry.mnemonic)
    stage2, stage2_idx := mt_ensure_s2(mt, entry)
    assert(stage2_idx != 0)
    // Create the first stage, if it doesn't exist
    stage1 := mt_add_s1(mt, entry.opcode)
    if !s1_present(stage1) {
        stage1.eop = entry.eop
        stage1.force_ds = entry.force_ds
        stage1.kind = entry.encoding_kind
        if entry.encoding_kind != .Rx_Extend {
            stage1.mnemonic = entry.mnemonic
        }
    }
    // If opcode has an rx extension, the intermediate table entry is generated
    // in the rx extensions table, otherwise stage1 connects to stage2 normally.
    if stage1.kind == .Rx_Extend {
        rx_exts: []RX_Ext_Encoding
        rx_exts_idx: int
        if stage1.entry_idx == 0 {
            rx_exts, rx_exts_idx = mt_add_rx_ext(mt)
            stage1.entry_idx = rx_exts_idx
        } else {
            rx_exts_idx = stage1.entry_idx
            rx_exts = mt.rx_table[rx_exts_idx][:]
        }
        assert(rx_exts[entry.rx_value].entry_idx == 0, "Attempt to put 2 entires int he same table")
        rx_exts[entry.rx_value].entry_idx = stage2_idx
        rx_exts[entry.rx_value].mnemonic = entry.mnemonic
    } else {
        assert(stage1.entry_idx == 0, "Attempt to write two encodings to the same first stage")
        stage1.entry_idx = stage2_idx
    }
}

