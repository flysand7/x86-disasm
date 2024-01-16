package elf

import "core:intrinsics"

Read_Error :: enum {
    None,
    Not_Found,
    Not_Elf,
    Bad_Elf,
    Not_Supported,
}

check_offset :: proc(elf: Elf_File, #any_int offset: uintptr) -> Read_Error {
    if 0 <= cast(uint) offset && cast(uint) offset < elf.size {
        return nil
    }
    return .Bad_Elf
}

verify_elf_header :: proc(elf: Elf_File) -> Read_Error {
    if elf.ehdr_sz != size_of(Ehdr) {
        return .Not_Elf
    }
    if size_of(elf.ident) != 16 {
        return .Not_Elf
    }
    if elf.ident[.Magic_0] != MAGIC0 {
        return .Not_Elf
    }
    if elf.ident[.Magic_1] != MAGIC1 {
        return .Not_Elf
    }
    if elf.ident[.Magic_2] != MAGIC2 {
        return .Not_Elf
    }
    if elf.ident[.Magic_3] != MAGIC3 {
        return .Not_Elf
    }
    if elf.ident[.Data] != u8(Endianness.Lsb) {
        return .Not_Supported
    }
    if elf.ident[.Version] != 1 {
        return .Not_Supported
    }
    if check_offset(elf, elf.sh_off) != nil {
        return .Bad_Elf
    }
    if elf.sh_ent_sz != size_of(Shdr) {
        return .Not_Supported
    }
    return nil
}

verify_zero_section :: proc(shdr: ^Shdr) -> Read_Error {
    if shdr.name != 0 {
        return .Bad_Elf
    }
    if shdr.type != Section_Type.Null {
        return .Bad_Elf
    }
    if shdr.flags != {} {
        return .Bad_Elf
    }
    if shdr.addr != 0 {
        return .Bad_Elf
    }
    if shdr.offset != 0 {
        return .Bad_Elf
    }
    if shdr.size != 0 {
        return .Bad_Elf
    }
    if shdr.link != SHN_UNDEF {
        return .Bad_Elf
    }
    if shdr.info != 0 {
        return .Bad_Elf
    }
    if shdr.address_align != 0 {
        return .Bad_Elf
    }
    if shdr.entry_size != 0 {
        return .Bad_Elf
    }
    return .Not_Elf
}
