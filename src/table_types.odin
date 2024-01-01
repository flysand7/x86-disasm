package disasm

Enc_Flags :: bit_set[enum{
    N64,
    Ncs,
    Ds,
    Ds1,
}]

Tab_Bits :: struct {
    value: u8,
    count: u8,
}

Ign_Bits :: struct {
    count: u8,
}

Tab_Field :: enum {
    // Opcode fields
    D,
    W,
    S,
    Tttt,
    Rrr,
    Eee,
    Ddd,
    Ss,
    Sss,
    Gg,
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
    // Implicit fields
    _a,
    _d,
    _64,
    _c,
    _1,
}

Tab_Mask :: union {
    Tab_Bits,
    Ign_Bits,
    Tab_Field,
}

Tab_Inst :: struct {
    name:   string,
    flags:  Enc_Flags,
    opcode: Tab_Bits,
    masks:  []Tab_Mask,
}

// 0 means it has dynamically-computed size or is just a flag
field_widths := [Tab_Field]u8 {
    .D     = 1,
    .W     = 1,
    .S     = 1,
    .Rrr   = 3,
    .Eee   = 3,
    .Ddd   = 3,
    .Tttt  = 4,
    .Gg    = 2,
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
    ._d    = 0,
    ._64   = 0,
    ._1    = 0,
    ._a    = 0,
    ._c    = 0,
}
