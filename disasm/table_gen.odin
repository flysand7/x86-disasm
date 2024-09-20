package x86_disasm
when !X86_USE_STUB {

Mnemonic :: enum {
    Mov,
}

mnemonic_table := [Mnemonic]string {
    .Mov = "mov",
}

stage1_table := [?]Stage1_Encoding {
    0x88 = {
        entry_idx = 1,
        eop = .None,
        kind = .Mod_Rm,
        force_ds = 0x1,
    },
    0x89 = {
        entry_idx = 2,
        eop = .None,
        kind = .Mod_Rm,
        force_ds = 0xff,
    },
    0x8a = {
        entry_idx = 3,
        eop = .None,
        kind = .Mod_Rm,
        force_ds = 0x1,
    },
    0x8b = {
        entry_idx = 4,
        eop = .None,
        kind = .Mod_Rm,
        force_ds = 0xff,
    },
    0x8c = {
        entry_idx = 5,
        eop = .None,
        kind = .Mod_Rm,
        force_ds = 0xff,
    },
    0x8e = {
        entry_idx = 6,
        eop = .None,
        kind = .Mod_Rm,
        force_ds = 0xff,
    },
    0xa0 = {
        entry_idx = 7,
        eop = .Disp,
        kind = .None,
        force_ds = 0x1,
    },
    0xa1 = {
        entry_idx = 8,
        eop = .Disp,
        kind = .None,
        force_ds = 0xff,
    },
    0xa2 = {
        entry_idx = 9,
        eop = .Disp,
        kind = .None,
        force_ds = 0x1,
    },
    0xa3 = {
        entry_idx = 10,
        eop = .Disp,
        kind = .None,
        force_ds = 0xff,
    },
    0xb0 = {
        entry_idx = 11,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0x1,
    },
    0xb1 = {
        entry_idx = 12,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0x1,
    },
    0xb2 = {
        entry_idx = 13,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0x1,
    },
    0xb3 = {
        entry_idx = 14,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0x1,
    },
    0xb4 = {
        entry_idx = 15,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0x1,
    },
    0xb5 = {
        entry_idx = 16,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0x1,
    },
    0xb6 = {
        entry_idx = 17,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0x1,
    },
    0xb7 = {
        entry_idx = 18,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0x1,
    },
    0xb8 = {
        entry_idx = 19,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0xff,
    },
    0xb9 = {
        entry_idx = 20,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0xff,
    },
    0xba = {
        entry_idx = 21,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0xff,
    },
    0xbb = {
        entry_idx = 22,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0xff,
    },
    0xbc = {
        entry_idx = 23,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0xff,
    },
    0xbd = {
        entry_idx = 24,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0xff,
    },
    0xbe = {
        entry_idx = 25,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0xff,
    },
    0xbf = {
        entry_idx = 26,
        eop = .Imm,
        kind = .Rx_Embed,
        force_ds = 0xff,
    },
    0xc6 = {
        entry_idx = 1,
        eop = .Imm,
        kind = .Rx_Extend,
        force_ds = 0x1,
    },
    0xc7 = {
        entry_idx = 2,
        eop = .Imm,
        kind = .Rx_Extend,
        force_ds = 0xff,
    },
}

rx_ext_table := [?][8]int {
    0 = {},
    1 = {27,0,0,0,0,0,0,0,},
    2 = {28,0,0,0,0,0,0,0,},
}

stage2_table := [?]Encoding {
    0 = {},
    1 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0xff,
    },
    2 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0xff,
    },
    3 = {
        mnemonic = .Mov,
        flags = {.D,},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0xff,
    },
    4 = {
        mnemonic = .Mov,
        flags = {.D,},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0xff,
    },
    5 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .SReg,
        rx_value = 0xff,
    },
    6 = {
        mnemonic = .Mov,
        flags = {.D,},
        rm_kind = .GPReg,
        rx_kind = .SReg,
        rx_value = 0xff,
    },
    7 = {
        mnemonic = .Mov,
        flags = {.D,},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x0,
    },
    8 = {
        mnemonic = .Mov,
        flags = {.D,},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x0,
    },
    9 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x0,
    },
    10 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x0,
    },
    11 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x0,
    },
    12 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x1,
    },
    13 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x2,
    },
    14 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x3,
    },
    15 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x4,
    },
    16 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x5,
    },
    17 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x6,
    },
    18 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x7,
    },
    19 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x0,
    },
    20 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x1,
    },
    21 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x2,
    },
    22 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x3,
    },
    23 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x4,
    },
    24 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x5,
    },
    25 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x6,
    },
    26 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x7,
    },
    27 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x0,
    },
    28 = {
        mnemonic = .Mov,
        flags = {},
        rm_kind = .GPReg,
        rx_kind = .GPReg,
        rx_value = 0x0,
    },
}

}
