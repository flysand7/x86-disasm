package elf

import "core:intrinsics"
import "core:slice"

Elf_File :: struct {
    using header: ^Ehdr,
    base:   [^]u8,
    size:   uint,
    strtab: []u8,
    symtab: []Sym,
}

file_from_bytes :: proc(bytes: []u8) -> (elf: Elf_File, err: Read_Error) {
    header := transmute(^Ehdr) raw_data(bytes)
    elf = Elf_File {
        header = header,
        base   = raw_data(bytes),
        size   = len(bytes),
    }
    verify_elf_header(elf) or_return
    symtab, _ := section_by_name(elf, ".symtab") or_return
    strtab, _ := section_by_name(elf, ".strtab") or_return
    elf.symtab = section_data(elf, symtab, Sym) or_return
    elf.strtab = section_data(elf, strtab, u8) or_return
    return elf, nil
}

section_data :: proc(elf: Elf_File, shdr: Shdr, $T: typeid) -> (data: []T, err: Read_Error) {
    offs := cast(uint) shdr.offset
    size := cast(uint) shdr.size
    if offs + size > elf.size {
        return nil, .Bad_Elf
    }
    bytes := transmute([^]T) elf.base[offs:]
    count := size / size_of(T)
    return bytes[:count], nil
}

section_list :: proc(elf: Elf_File) -> (sections: []Shdr, err: Read_Error) {
    sections = (transmute([^]Shdr) elf.base[elf.sh_off:])[:elf.sh_ent_cnt]
    return sections, nil
}

section_by_index :: proc(elf: Elf_File, #any_int i: uintptr) -> (section: Shdr, err: Read_Error) {
    if i >= cast(uintptr) elf.sh_ent_cnt {
        return {}, .Bad_Elf
    }
    return (transmute([^]Shdr) elf.base[elf.sh_off:])[i], nil
}

section_name :: proc(elf: Elf_File, shdr: Shdr) -> (name: string, err: Read_Error) {
    assert(elf.str_sec_ndx != 0)
    strtab_sh := section_by_index(elf, elf.str_sec_ndx) or_return
    strtab := section_data(elf, strtab_sh, u8) or_return
    name = cast(string) transmute(cstring) &strtab[shdr.name]
    return name, nil
}

section_by_name :: proc(elf: Elf_File, name: string) -> (section: Shdr, idx: int, err: Read_Error) {
    assert(elf.str_sec_ndx != 0)
    strtab_sh := section_by_index(elf, elf.str_sec_ndx) or_return
    strtab := section_data(elf, strtab_sh, u8) or_return
    sections := section_list(elf) or_return
    for section, idx in sections {
        section_name := cast(string) transmute(cstring) &strtab[section.name]
        if section_name == name {
            return section, idx, nil
        }
    }
    return {}, 0, .Not_Found
}

symbol_list :: proc(elf: Elf_File) -> (syms: []Sym) {
    return elf.symtab
}

symbol_name :: proc(elf: Elf_File, sym: Sym) -> (name: string, err: Read_Error) {
    if cast(int) sym.name >= len(elf.strtab) {
        return {}, .Bad_Elf
    }
    return cast(string) transmute(cstring) raw_data(elf.strtab[sym.name:]), nil
}

symbol_info :: proc(sym: Sym) -> (Sym_Type, Sym_Bind) {
    type := transmute(Sym_Type) (sym.info & 0xf)
    bind := transmute(Sym_Bind) (sym.info >> 4)
    return type, bind
}

symbol_visibility :: proc(sym: Sym) -> Sym_Visibility {
    return transmute(Sym_Visibility) (sym.other & 0x3)
}
