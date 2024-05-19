package format_generic

import "pe"
import "core:slice"

is_pe :: proc(file_contents: []u8) -> bool {
    bytes := transmute([^]u8) raw_data(file_contents)
    if len(file_contents) < pe.PE_SIGNATURE_OFFSET + size_of(u32) {
        return false
    }
    magic_offset := (transmute(^u32le) &bytes[pe.PE_SIGNATURE_OFFSET])^
    if len(file_contents) < int(magic_offset) + size_of(u32) {
        return false
    }
    header_magic := (transmute(^u32le) &bytes[magic_offset])^
    if header_magic != pe.PE_SIGNATURE {
        return false
    }
    if len(file_contents) < int(magic_offset) + size_of(u32) + size_of(pe.File_Header) {
        return false
    }
    file_header := (transmute(^pe.File_Header) &bytes[magic_offset + size_of(u32)])^
    if !(file_header.machine == .AMD64 || file_header.machine == .I386) {
        return false
    }
    return true
}

pe_parse :: proc(file_contents: []u8) -> (File, bool) {
    // Find the COFF header.
    bytes := transmute([^]u8) raw_data(file_contents)
    magic_offset := int((transmute(^u32le) &bytes[pe.PE_SIGNATURE_OFFSET])^)
    file_header := transmute(^pe.File_Header) &bytes[magic_offset + size_of(u32)]
    if .BYTES_REVERSED_HI in file_header.characteristics {
        return {}, false
    }
    // Get what we need from the file header.
    generic_machine: Machine = ---
    #partial switch file_header.machine {
        case .AMD64: generic_machine = .X86_64
        case .I386:  generic_machine = .X86_32
        case: generic_machine = .Unknown
    }
    n_sections := int(file_header.number_of_sections)
    n_symbols := int(file_header.number_of_symbols)
    symtab_offs := int(file_header.pointer_to_symbol_table)
    opt_hdr_sz := int(file_header.size_of_optional_header)
    // Verify the symbol table pointer.
    if len(file_contents) < symtab_offs + n_symbols*size_of(pe.COFF_Symbol) {
        return {}, false
    }
    // Find the optional header.
    opt_hdr_offs := magic_offset + size_of(u32) + size_of(pe.File_Header)
    if len(file_contents) < opt_hdr_offs + opt_hdr_sz {
        return {}, false
    }
    opt_hdr_base := (transmute(^pe.Optional_Header_Base) &bytes[opt_hdr_offs])^
    rva_base := u64(opt_hdr_base.base_of_code)
    // Find the string table.
    strtab_offs := symtab_offs + n_symbols*size_of(pe.COFF_Symbol)
    strtab_sz := int((transmute(^u32le) &bytes[strtab_offs])^) - size_of(u32)
    strtab := transmute([^]u8) &bytes[strtab_offs+size_of(u32)]
    if strtab_offs != 0 && len(file_contents) < strtab_offs + size_of(u32) + strtab_sz {
        return {}, false
    }
    // Load sections.
    sections_ptr := transmute([^]pe.Section_Header32) &bytes[opt_hdr_offs + opt_hdr_sz]
    sections := cast([]pe.Section_Header32) sections_ptr[:n_sections]
    generic_sections := make([dynamic]Section)
    for section in sections {
        nul_terminator_pos := 8
        section_name_arr := section.name
        for c, i in transmute([]u8) section_name_arr[:] {
            if c == 0 {
                nul_terminator_pos = i
                break
            }
        }
        section_name := transmute(string) section_name_arr[:nul_terminator_pos]
        if section_name[0] == '/' {
            if symtab_offs == 0 {
                return {}, false
            }
            strtab_idx := 0
            for d in section_name[1:] {
                strtab_idx = strtab_idx*10 + int(d-'0')
            }
            if strtab_idx >= strtab_sz {
                return {}, false
            }
            // TODO: Potential OOB on seeking for NUL-terminator.
            section_name = cast(string) transmute(cstring) &strtab[strtab_idx]
        }
        section_data := cast([^]u8) &bytes[section.pointer_to_raw_data]
        section_size := int(section.virtual_size)
        generic_section := Section {
            name = section_name,
            vaddr = rva_base + u64(section.virtual_address),
            bytes = section_data[:section_size]
        }
        append(&generic_sections, generic_section)
    }
    // Find .pdata and .text sections
    pdata: []pe.Runtime_Function = nil
    text: []u8 = nil
    for section in generic_sections {
        if section.name == ".pdata" {
            pdata = slice.reinterpret(type_of(pdata), section.bytes)
        } else if section.name == ".text" {
            text = section.bytes
        }
    }
    if text == nil {
        return {}, false
    }
    if pdata == nil {
        // TODO(flysand): If .pdata isn't present we need a backup plan
        // where we 
        return {}, false
    }
    // Load symbols
    symbols_ptr := transmute([^]pe.COFF_Symbol) &bytes[symtab_offs]
    symbols := cast([]pe.COFF_Symbol) symbols_ptr[:n_symbols]
    generic_symbols := make([dynamic]Symbol)
    // TODO(flysand): The code for reading the name from the symbol table might
    // get extracted into a separate procedure.
    symbol_idx := 0
    for symbol_idx < n_symbols {
        symbol := symbols[symbol_idx]
        nul_terminator_pos := 8
        symbol_name_arr := symbol.name
        for c, i in transmute([]u8) symbol_name_arr[:] {
            if c == 0 {
                nul_terminator_pos = i
                break
            }
        }
        symbol_name := transmute(string) symbol_name_arr[:nul_terminator_pos]
        if symbol_name[0] == '/' {
            if symtab_offs == 0 {
                return {}, false
            }
            strtab_idx := 0
            for d in symbol_name[1:] {
                strtab_idx = strtab_idx*10 + int(d-'0')
            }
            if strtab_idx >= strtab_sz {
                return {}, false
            }
            // TODO: Potential OOB on seeking for NUL-terminator.
            symbol_name = cast(string) transmute(cstring) &strtab[strtab_idx]
        }
        if symbol.type == .DTYPE_FUNCTION {
            generic_symbol := Symbol {
                name = symbol_name,
                section_no = int(symbol.section_number),
                vaddr = rva_base + u64(symbol.value),
            }
            append(&generic_symbols, generic_symbol)
        }
        symbol_idx += 1+int(symbol.number_of_aux_symbols)
    }
    return File {
        format = .PE,
        machine = generic_machine,
        sections = generic_sections[:],
        symbol = generic_symbols[:],
        type = .Executable,
    }, true
}