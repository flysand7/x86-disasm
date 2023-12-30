package disasm

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
    Tttn,
    Reg,
    Eee,
    // Modrm
    Mod,
    Moda,
    Modb,
    Modab,
    Rx,
    Rm,
    // Bytes
    Sel,
    Imm,
    Imm8,
    Disp,
    Disp8,
    // Implicit fields
    Rega,
    _d0,
}

Tab_Mask :: union {
    Tab_Bits,
    Ign_Bits,
    Tab_Field,
}

Tab_Inst :: struct {
    name: string,
    opcode: Tab_Bits,
    masks: []Tab_Mask,
}

// 0 means it has dynamically-computed size or is just a flag
field_widths := [Tab_Field]u8 {
    .D     = 1,
    .W     = 1,
    .S     = 1,
    .Reg   = 3,
    .Eee   = 3,
    .Tttn  = 4,
    .Mod   = 2,
    .Moda  = 2,
    .Modb  = 2,
    .Modab = 2,
    .Rx    = 3,
    .Rm    = 3,
    .Sel   = 0,
    .Imm   = 0,
    .Imm8  = 0,
    .Disp  = 0,
    .Disp8 = 0,
    .Rega  = 0,
    ._d0    = 0,
}
