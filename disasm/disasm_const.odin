package x86_disasm

// Instruction prefixes.
PREFIX_LOCK  :: u8(0xf0)
PREFIX_REPNZ :: u8(0xf2)
PREFIX_REPZ  :: u8(0xf3)
PREFIX_CS    :: u8(0x2e)
PREFIX_SS    :: u8(0x36)
PREFIX_DS    :: u8(0x3e)
PREFIX_ES    :: u8(0x26)
PREFIX_FS    :: u8(0x64)
PREFIX_GS    :: u8(0x65)
PREFIX_BT    :: u8(0x2e)
PREFIX_BN    :: u8(0x3e)
PREFIX_DATA  :: u8(0x66)
PREFIX_ADDR  :: u8(0x67)

// The REX byte.
REX_MAGIC :: u8(0x40)
REX_Byte :: bit_field u8 {
    b: u8 | 1,
    x: u8 | 1,
    r: u8 | 1,
    w: u8 | 1,
    magic: u8 | 4,
}

// The Mod/RM byte.
ModRM_Byte :: bit_field u8 {
    rm:  u8 | 3,
    rx:  u8 | 3,
    mod: u8 | 2,
}

// The SIB byte.
SIB_Byte :: bit_field u8 {
    sb: u8 | 3,
    si: u8 | 3,
    ss: u8 | 2,
}
