package disasm_table

ENABLE_DEBUG_ASSERT :: #config(ENABLE_DEBUG_ASSERT, true)

@(disabled=!ENABLE_DEBUG_ASSERT)
dbg_assert :: proc(c: bool, s := "") {
    assert(c, s)
}

Mod :: enum {
    Mod_00,
    Mod_01,
    Mod_10,
    Mod_11,
}

Mod_Kind :: enum {
    None,       // Instruction has no mod field.
    Normal,     // Represents 2 operands encoded in rx and rm fields.
    Opcode_Ext, // An opcode extension in rx, and an operand encoded in rm.
    Opcode,     // The whole byte is an opcode extension.
}

Data_Prefix :: enum {
    Prefix_Np,
    Prefix_66,
    Prefix_F3,
    Prefix_F2,
}

Opcode_Prefix :: enum {
    None,
    Opcode_0f,
    Opcode_0f38,
    Opcode_0f3a,
}

Reg_Set :: enum u8 {
    Reg,
    Mmx,
    Xmm,
    Sreg,
    Dreg,
    Creg,
    Bndreg,
    St,
    Extras,
}

Encoding_Flags :: enum u8 {
    Is_Slice,
    Rx_Ext,
    Rx_Value,
    D,
    W,
    Vex_Vz,
    Far,
    Rep,
}

Extra_Operand_Kind :: enum u8 {
    None,
    Imm8,
    Imm16,
    Imm32,
    Imm_R,
    Imm,
    Imm16imm8,
    Rel8,
    Rel16,
    Rel32,
    Rel,
    Far16,
    Far32,
    Far,
    Xmmimm,
}

Encoding :: struct {
    mnemonic: u16,
    cst_line: CST_Line,
    rmx_line: RMX_Line,
    flg_line: FLG_Line,
}

CST_Line :: distinct u16
RMX_Line :: distinct u16
FLG_Line :: distinct u16

/*
    Layout for the prefix line

    5      4              2               0
    +------+--------------+---------------+
    | VEX? |  Data Prefix | Opcode Prefix |
    +------+--------------+---------------+
      1 bit      2 bits         2 bits
*/
make_pfx_line :: proc(vex: bool, dp: Data_Prefix, opp: Opcode_Prefix) -> u8 {
    vx := cast(u8) vex
    dp := cast(u8) dp
    op := cast(u8) opp
    dbg_assert(dp<4, "Data prefix is bad")
    dbg_assert(op<4, "Opcode prefix is bad")
    return auto_cast (op | dp<<2 | vx<<4)
}

/*
    Layout for the constraint line

     16         14     12          8          6            3            0
      +----------+------+----------+----------+------------+------------+
      | Mod Kind | vexw | Mod Bits | CPU Mode | Data Sizes | Addr Sizes |
      +----------+------+----------+----------+------------+------------+
         2 bits   2 bits   4 bits     2 bits      3 bits      3 bits
    
    vexw - specifies which bits of VEX.W prefix are allowed. Bit 0 of this
    field specifies whether VEX.W=0 is allowed and bit 1 specifies whether
    VEX.W=1 is allowed.
*/
make_cst_line :: proc(
    vex_w: u8,
    mod_kind: Mod_Kind,
    mod:  bit_set[Mod],
    cpu:  bit_set[Size],
    data: bit_set[Size],
    addr: bit_set[Size],
) -> CST_Line {
    vex_w := cast(u16) vex_w
    mod_kind := cast(u16) mod_kind
    mod  := cast(u16) transmute(u8) mod
    cpu  := cast(u16) transmute(u8) cpu
    cpu >>= 2
    cpu &= 0b11
    data := cast(u16) transmute(u8) data
    data >>= 2
    data &= 0b111
    addr := cast(u16) transmute(u8) addr
    addr >>= 2
    addr &= 0b111
    return auto_cast (addr | data<<3 | cpu<<6 | mod<<8 | vex_w<<12 | mod_kind<<14)
}

make_cst_line_specific :: proc(
    vex_w: bool,
    mod:   bit_set[Mod],
    cpu:   Size,
    data:  Size,
    addr:  Size,
) -> CST_Line {
    cpu := cpu
    if cpu == .Size_16 {
        cpu = .Size_32
    }
    vex_w := u16(1) << u8(vex_w)
    mod   := u16(1) << transmute(u8) mod
    cpu_i := cast(u16) (u8(1) << (u8(cpu)-3))
    data  := cast(u16) (u8(1) << (u8(data)-2))
    addr  := cast(u16) (u8(1) << (u8(addr)-2))
    dbg_assert(cpu_i<1<<3)
    dbg_assert(data<1<<3)
    dbg_assert(addr<1<<3)
    return auto_cast (addr | data<<3 | cpu_i<<6 | mod<<8 | vex_w<<12)
}

/*
    Layout for rmx line.

   16    15    12     9     6     3     0
    +-----+-----+-----+-----+-----+-----+
    | rmm | rmt | rms | rxt | rxs | rxi |
    +-----+-----+-----+-----+-----+-----+
      1b    3b    3b    3b    3b    3b

    rmm - memory modified bit. If set, modifies the size of memory.
          if unset, modifies both memory and registers.
    rmt - type of register specified by RM
    rms - size of operand specified by RM
    rxt - type of register specified by RX
    rxs - size of register specified by RX
        - if mod/rm fully extends the opcode, holds the rm field value.
    rxi - index of register specified by RX
        - if mod/rm extends the opcode, holds the extension bytes
 */
 make_rmx_line :: proc(rmm: b8, rmt, rxt: Reg_Set, rms, rxs: Size, rxi: u8) -> RMX_Line {
    rmm := cast(u16) rmm
    rmt := cast(u16) rmt
    rms := cast(u16) rms
    rxt := cast(u16) rxt
    rxs := cast(u16) rxs
    rxi := cast(u16) rxi
    return auto_cast (rxi | rxs<<3 | rxt<<6 | rms<<9 | rmt<<12 | rmm<<15)
}

/*
    Layout for flags line.

   16     11    8        0
   +-------+----+--------+
   |  eop  | ds | flags  |
   +-------+----+--------+
      5b     3b     5b

    eop - number of an extra operand.
    ds - data size override.
    flg - encoding flags.
*/
make_flg_line :: proc(
    ds:  Size,
    flg: bit_set[Encoding_Flags; u8],
    eop: Extra_Operand_Kind,
) -> (FLG_Line) {
    dbg_assert(cast(int) ds < 1<<3)
    dbg_assert(len(Encoding_Flags) <= 8)
    dbg_assert(cast(int) eop < 1<<5)
    ds := cast(u16) ds
    flg := cast(u16) transmute(u8) flg
    eop := cast(u16) eop
    return cast(FLG_Line) (flg | ds<<8 | eop<<11)
}

@(private)
flg_set :: proc(f: FLG_Line, bit: Encoding_Flags) -> FLG_Line {
    rest := u16(f)
    flags := transmute(bit_set[Encoding_Flags; u16]) cast(u16) (f & 0b11111111)
    flags += {bit}
    return cast(FLG_Line) (rest | transmute(u16) flags)
}

@(private)
flg_isset :: proc(f: FLG_Line, bit: Encoding_Flags) -> bool {
    flags := transmute(bit_set[Encoding_Flags; u16]) cast(u16) (f & 0b11111111)
    return bit in flags
}

encoding_slice_index :: proc(e: Encoding) -> (u16) {
    dbg_assert(.Is_Slice in encoding_flags(e), "Trying to get slice index of non-slice encoding")
    return e.mnemonic
}

encoding_mnemonic_idx :: proc(e: Encoding) -> u16 {
    dbg_assert(.Is_Slice not_in encoding_flags(e), "Trying to get mnemonic of slice encoding")
    return e.mnemonic
}

encoding_cst_mask :: proc(e: Encoding) -> u16 {
    return u16(e.cst_line) & (1<<14-1)
}

cst_mask :: proc(c: CST_Line) -> u16 {
    return u16(c) & (1<<14-1)
}

encoding_mod_kind :: proc(e: Encoding) -> Mod_Kind {
    return cast(Mod_Kind) ((u16(e.cst_line)>>14) & 0b11)
}

@(private)
cst_mod_kind :: proc(c: CST_Line) -> Mod_Kind {
    return cast(Mod_Kind) ((u16(c)>>14) & 0b11)
}

encoding_mods :: proc(cl: CST_Line) -> bit_set[Mod] {
    return transmute(bit_set[Mod]) ((u8(cl)>>8)&0b1111)
}

encoding_rm_size :: proc(e: Encoding, mod: u8, ds: Size) -> Size {
    rmm := (e.rmx_line >> 15) != 0
    rms := cast(Size) ((e.rmx_line >> 9) & 0b111)
    if rms == .Default || (rmm && mod == 0b11) {
        return ds
    }
    return rms
}

encoding_rx_size :: proc(e: Encoding, ds: Size) -> Size {
    rxs := cast(Size) ((e.rmx_line >> 3) & 0b111)
    if rxs == .Default {
        return ds
    }
    return rxs
}

encoding_rm_type :: proc(e: Encoding) -> Reg_Set {
    return cast(Reg_Set) ((e.rmx_line >> 12) & 0b111)
}

encoding_rx_type :: proc(e: Encoding) -> Reg_Set {
    return cast(Reg_Set) ((e.rmx_line >> 6) & 0b111)
}

encoding_rx :: proc(e: Encoding) -> u8 {
    return cast(u8) (e.rmx_line & 0b111)
}

encoding_modrm :: proc(e: Encoding) -> (u8, u8, u8) {
    mod := cast(u8) ((u16(e.cst_line)>>12) & 0b11)
    rx := cast(u8) (e.rmx_line & 0b111)
    rm := cast(u8) ((e.rmx_line >> 3) & 0b111)
    return mod, rx, rm
}

@(private)
rmx_rm :: proc(r: RMX_Line) -> (u8) {
    rm := cast(u8) ((r >> 3) & 0b111)
    return rm
}


encoding_data_override :: proc(e: Encoding) -> Size {
    return cast(Size) ((e.flg_line>>8) & 0b111)
}

encoding_flags :: proc(e: Encoding) -> bit_set[Encoding_Flags; u8] {
    return transmute(bit_set[Encoding_Flags; u8]) cast(u8) (e.flg_line & 0b1111111)
}

encoding_extra_op :: proc(e: Encoding) -> Extra_Operand_Kind {
    return cast(Extra_Operand_Kind) ((e.flg_line >> 11) & 0b11111)
}

Size :: enum u8 {
    Default  = 0,
    Size_8   = 1,
    Size_16  = 2,
    Size_32  = 3,
    Size_64  = 4,
    Size_128 = 5,
    Size_256 = 6,
    Size_512 = 7,
}

size_to_bytes :: proc(s: Size) -> int {
    return cast(int) (1<<(cast(uint)s - 1))
}
