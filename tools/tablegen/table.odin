package tablegen

DS_DEFAULT :: u8(0xff)

REG_NONE :: u8(0xff)
REG_AX :: u8(0b000)
REG_CX :: u8(0b001)
REG_DX :: u8(0b010)
REG_BX :: u8(0b011)
REG_SP :: u8(0b100)
REG_BP :: u8(0b101)
REG_SI :: u8(0b110)
REG_DI :: u8(0b111)

RX_Kind :: enum {
    None,
    GPReg,
    SReg,
}

RM_Kind :: enum {
    None,
    GPReg,
}

EOP_Kind :: enum {
    None,
    Imm,
    Imm8,
    Disp,
    NDisp,
    FDisp,
}

Table_Entry_Flag :: enum {
    D,
}

Encoding_Kind :: enum {
    None,
    Rx_Extend, // bb /[n]
    Rx_Embed,  // bb^
    Mod_Rm,    // bb /rk
}

Table_Entry :: struct {
    src_line: int,
    mnemonic: string,
    flags: bit_set[Table_Entry_Flag],
    force_ds: u8,
    opcode: u8,
    encoding_kind: Encoding_Kind,
    eop: EOP_Kind,
    rx_value: u8, // Can be REG_NONE
    rx_kind: RX_Kind,
    rm_kind: RM_Kind,
}
