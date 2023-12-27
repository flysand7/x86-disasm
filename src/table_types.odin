package disasm

Tab_Bits :: struct {
    value: u8,
    count: u8,
}

Tab_Field :: enum {
    D,
    W,
    Mod,
    Rx,
    Rm,
    Imm,
    Disp,
    Rega,
}

Tab_Mask :: union {
    Tab_Bits,
    Tab_Field,
}

Tab_Inst :: struct {
    name: string,
    opcode: Tab_Bits,
    masks: []Tab_Mask,
}

// 0 means it has dynamically-computed size or is just a flag
field_widths := [Tab_Field]u8 {
    .D    = 1,
    .W    = 1,
    .Mod  = 2,
    .Rx   = 3,
    .Rm   = 3,
    .Imm  = 0,
    .Disp = 0,
    .Rega = 0,
}
