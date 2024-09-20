package x86_disasm

// Stub contains basic definitions for LSPs and tools to work without a
// generated table.
X86_USE_STUB :: #config(X86_USE_STUB, true)

Encoding_Flag :: enum {
    D,
}

Encoding_Kind :: enum {
    None,
    Rx_Extend, // bb /[n]
    Rx_Embed,  // bb^
    Mod_Rm,   // bb /rk
}

Encoded_EOP_Kind :: enum {
    None,
    Imm,
    Disp,
}

Stage1_Encoding :: struct {
    kind: Encoding_Kind,
    entry_idx: int,
    eop: Encoded_EOP_Kind,
    force_ds: u8,
}

Encoding :: struct {
    mnemonic: Mnemonic,
    flags: bit_set[Encoding_Flag],
    rx_value: u8,
    rx_kind: RX_Op_Kind,
    rm_kind: RM_Op_Kind,
}