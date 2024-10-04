package x86_disasm

when X86_USE_STUB {

    Mnemonic :: enum {
        Mov,
    }
    
    // Contains deduplicated strings, corresponding to instruction mnemonics.
    mnemonic_table := [Mnemonic]string {
        .Mov = "mov"
    }

    // The first stage of the disassembly:
    // This stage is indexed by the opcode byte, and is used to figure out
    // the presence of the mod/rm byte and the extra operand. In theory the
    // first stage is all we need to determine the length of instruction in
    // bytes. This stage also stores the kind of encoding, that determines
    // how we access the second stage.
    // If the encoding kind is RX-extend, the `rx_ext_table` will contain
    // an array of 8 indices to the second stage. The array of 8 indices
    // is accessed using `rx` field of the mod/rm byte.
    // Otherwise the index in stage1 directly points to stage2.
    stage1_table := [?]Stage1_Encoding {}

    // The intermediate rx opcode extension table.
    // First index is a reference to the extension group, stored in stage 1.
    // Second index is the `rx` field of the mod/rm byte.
    // The stored index is the index of the stage2 entry.
    rx_ext_table := [?][8]RX_Ext_Encoding {}

    // The second stage of the disassembly:
    // Contains information necessary to interpret the bytes of instruction.
    stage2_table := [?]Encoding {}

}