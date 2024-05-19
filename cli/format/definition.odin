package generic

Format_Type :: enum {
    Unknown,
    PE,
    COFF,
    ELF,
}

File_Type :: enum {
    Unknown,
    Relocatable,
    Executable,
    Shared,
}

Machine :: enum {
    Unknown,
    X86_16,
    X86_32,
    X86_64,
}

File :: struct {
    format: Format_Type,
    type: File_Type,
    machine: Machine,
    sections: []Section,
    symbol: []Symbol,
}

Section :: struct {
    name: string `fmt:s`,
    bytes: []u8 `fmt:"-"`,
    vaddr: u64,
}

Symbol :: struct {
    name: string,
    vaddr: u64,
    section_no: int,
    bytes: []u8 `fmt:"-"`,
}
