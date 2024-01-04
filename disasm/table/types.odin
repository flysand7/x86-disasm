package disasm_data

Enc_Flags :: bit_set[enum{
    Flag_N64,
    Flag_F64,
    Flag_Ncs,
    Flag_Ds,
    Flag_Ds1,
    Flag_Np,
    Flag_Dp,
    Flag_F2,
    Flag_F3,
    Flag_0f,
    Flag_3a,
    Flag_38,
    Flag_Vp,
}]

Bits :: struct {
    value: u8,
    count: u8,
}

Ign :: struct {
    count: u8,
}

Field :: enum {
    // Opcode fields
    D,
    W,
    S,
    Rrr,
    Eee,
    Ddd,
    Ss,
    Sss,
    // Modrm
    Mod,
    Moda,
    Modb,
    Modab,
    Mod11,
    Rx,
    Rm,
    Mmxrx,
    Xmmrx,
    Mmrx,
    // Bytes
    Sel,
    Imm,
    Imm8,
    Imm16,
    Disp,
    Disp8,
    Disp16,
    // Implicit fields
    _a,
    _d,
    _64,
    _c,
    _1,
    _fs,
    _gs,
}

Bit_Mask :: union {
    Bits,
    Ign,
    Field,
}

Encoding :: struct {
    mnemonic: string,
    flags:    Enc_Flags,
    opcode:   Bits,
    masks:    []Bit_Mask,
}

// 0 means it has dynamically-computed size or is just a flag
field_widths := [Field]u8 {
    .D     = 1,
    .W     = 1,
    .S     = 1,
    .Rrr   = 3,
    .Eee   = 3,
    .Ddd   = 3,
    .Ss    = 2,
    .Sss   = 3,
    .Mod   = 2,
    .Moda  = 2,
    .Modb  = 2,
    .Modab = 2,
    .Mod11 = 2,
    .Rx    = 3,
    .Rm    = 3,
    .Mmxrx = 3,
    .Xmmrx = 3,
    .Mmrx  = 3,
    .Sel   = 0,
    .Imm   = 0,
    .Imm8  = 0,
    .Imm16 = 0,
    .Disp  = 0,
    .Disp8 = 0,
    .Disp16 = 0,
    ._d    = 0,
    ._64   = 0,
    ._1    = 0,
    ._a    = 0,
    ._c    = 0,
    ._fs   = 0,
    ._gs   = 0,
}
