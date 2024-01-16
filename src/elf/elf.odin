package elf

Object_Type :: enum u16 {
    None        = 0,
    Relocatable = 1,
    Executable  = 2,
    Shared      = 3,
    Core        = 4,
}

Machine :: enum u16 {
    None        = 0,
    i386        = 3,
    Arm         = 40,
    x64         = 62,
}

Elf_Version :: enum u32 {
    None        = 0,
    Current     = 1,
}

Identification :: enum {
    Magic_0     = 0,
    Magic_1     = 1,
    Magic_2     = 2,
    Magic_3     = 3,
    Class       = 4,
    Data        = 5,
    Version     = 6,
    OS_Abi         = 7,
    Abi_Version = 8,
    _0          = 9,
    _1          = 10,
    _2          = 11,
    _3          = 12,
    _4          = 13,
    _5          = 14,
    _6          = 15,
}

MAGIC0 :: u8(0x7f)
MAGIC1 :: u8('E')
MAGIC2 :: u8('L')
MAGIC3 :: u8('F')

Class :: enum u8 {
    None  = 0,
    Elf32 = 1,
    Elf64 = 2,
}

Endianness :: enum u8 {
    None = 0,
    Lsb  = 1,
    Msb  = 2,
}

OS_Abi :: enum u8 {
    None     = 0,
    Net_BSD  = 2,
    Linux    = 3,
    Free_BSD = 9,
}

SHN_UNDEF  :: 0
SHN_ABS    :: 0xfff1
SHN_COMMON :: 0xfff2
SHN_XINDEX :: 0xffff

Ehdr :: struct {
    ident:       [Identification]u8,
    type:        Object_Type,
    machine:     Machine,
    version:     Elf_Version,
    entry:       uintptr,
    ph_off:      uintptr,
    sh_off:      uintptr,
    flags:       u32,
    ehdr_sz:     u16,
    ph_ent_sz:   u16,
    ph_ent_cnt:  u16,
    sh_ent_sz:   u16,
    sh_ent_cnt:  u16,
    str_sec_ndx: u16,
}

Section_Type :: enum u32 {
    Null          = 0,
    Progbits      = 1,
    Symtab        = 2,
    Strtab        = 3,
    Rela          = 4,
    Hash          = 5,
    Dynamic       = 6,
    Note          = 7,
    Nobits        = 8,
    Rel           = 9,
    Shlib         = 10,
    Dynsym        = 11,
    Init_Array    = 14,
    Fini_Array    = 15,
    Preinit_Array = 16,
    Group         = 17,
    Symtab_Index  = 18,
}

Section_Flag_Bit :: enum {
    Write             = 0,
    Alloc             = 1,
    Exec              = 2,
    Merge             = 3,
    Strings           = 4,
    Info_link         = 5,
    Link_Order        = 6,
    Os_Non_Conforming = 7,
    Group             = 8,
    TLS               = 9,
}

Section_Flags :: bit_set[Section_Flag_Bit; uint]

Section_Group_Flags :: bit_set[enum{
    Comdat = 0,
}; u32]

Shdr :: struct {
    name:          u32,
    type:          Section_Type,
    flags:         Section_Flags,
    addr:          uintptr,
    offset:        uintptr,
    size:          uint,
    link:          u32,
    info:          u32,
    address_align: uint,
    entry_size:    uint,
}

Segment_Type :: enum u32 {
    Null    = 0,
    Load    = 1,
    Dynamic = 2,
    Interp  = 3,
    Note    = 4,
    Shlib   = 5,
    Phdr    = 6,
    Tls     = 7,
}

Segment_Flags :: bit_set[enum {
    X = 0,
    W = 1,
    R = 2,
}; u32]

Phdr32 :: struct {
    type:   Segment_Type,
    offset: uint,
    vaddr:  uintptr,
    paddr:  uintptr,
    filesz: uint,
    memsz:  uint,
    flags:  Segment_Flags,
    align:  uint,
}

Phdr :: struct {
    type:   Segment_Type,
    flags:  Segment_Flags,
    offset: uint,
    vaddr:  uintptr,
    paddr:  uintptr,
    filesz: uint,
    memsz:  uint,
    align:  uint,
}

Sym32 :: struct {
    name:  u32,
    value: uintptr,
    size:  u32,
    info:  u8,
    other: u8,
    shidx: u16,
}

Sym_Bind :: enum u8 {
    Local  = 0,
    Global = 1,
    Weak   = 2,
}

Sym_Type :: enum u8 {
    Notype  = 0,
    Object  = 1,
    Func    = 2,
    Section = 3,
    File    = 4,
    Common  = 5,
    Tls     = 6,
}

Sym_Visibility :: enum u8 {
    Default   = 0,
    Internal  = 1,
    Hidden    = 2,
    Protected = 3,
    Exported  = 4,
    Singleton = 5,
    Eliminate = 6,
}

Sym :: struct {
    name:  u32,
    info:  u8,
    other: u8,
    shndx: u16,
    value: uintptr,
    size:  u64,
}
