package format_generic

import "pe"
import "core:fmt"
import "core:slice"

is_coff :: proc(file_contents: []u8) -> bool {
    bytes := transmute([^]u8) raw_data(file_contents)
    if len(file_contents) < size_of(pe.File_Header) {
        return false
    }
    file_header := transmute(^pe.File_Header) bytes
    // Note(flysand): COFF files do not have a magic number per se.
    // since this is a disassembler focusing on disassembling x86 code we will
    // just use the machine number as our magic number. Luckily for us this
    // doesn't cause collision with any other file formats we're interested in
    // even the 'raw' format, since both of the machine numbers we're looking
    // at don't disassemble to a valid instruction.
    // In case that isn't desired anyway, this tool provides '-format' option
    // that allows to set the type 'raw' explicitly and avoid this unreliable
    // COFF detection.
    if file_header.machine == .AMD64 || file_header.machine == .I386 {
        return true
    }
    return false
}

pdata_find_record :: proc(pdata: []pe.Runtime_Function, addr: u32le) -> (pe.Runtime_Function, bool) {
    key := pe.Runtime_Function {
        begin_addr = addr,
    }
    idx, ok := slice.binary_search_by(pdata, key, proc (a, b: pe.Runtime_Function) -> slice.Ordering {
        return \
            .Equal   if a.begin_addr == b.begin_addr else
            .Less    if a.begin_addr  < b.begin_addr else
            .Greater if a.begin_addr  > b.begin_addr else nil

    })
    if idx == -1 || idx >= len(pdata) {
        return {}, false
    }
    if pdata[idx].begin_addr != addr {
        return {}, false
    }
    return pdata[idx], ok
}

coff_parse :: proc(file_contents: []u8) -> (File, bool) {
    // Find the COFF header.
    bytes := transmute([^]u8) raw_data(file_contents)
    file_header := transmute(^pe.File_Header) &bytes[0]
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
    opt_hdr_offs := size_of(pe.File_Header)
    if len(file_contents) < opt_hdr_offs + opt_hdr_sz {
        return {}, false
    }
    opt_hdr_base := (transmute(^pe.Optional_Header_Base) &bytes[opt_hdr_offs])^
    rva_base := u64(opt_hdr_base.base_of_code)
    // Find the string table.
    strtab_offs := symtab_offs + n_symbols*size_of(pe.COFF_Symbol)
    strtab_sz := int((transmute(^u32le) &bytes[strtab_offs])^)
    strtab := transmute([^]u8) &bytes[strtab_offs]
    if strtab_offs != 0 && len(file_contents) < strtab_offs + strtab_sz {
        return {}, false
    }
    // Load sections.
    sections_ptr := transmute([^]pe.Section_Header32) &bytes[opt_hdr_offs + opt_hdr_sz]
    sections := cast([]pe.Section_Header32) sections_ptr[:n_sections]
    generic_sections := make([dynamic]Section)
    for &section in sections {
        nul_terminator_pos := 8
        for c, i in section.name {
            if c == 0 {
                nul_terminator_pos = i
                break
            }
        }
        section_name := transmute(string) section.name[:nul_terminator_pos]
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
        section_size := int(section.size_of_raw_data)
        generic_section := Section {
            name = section_name,
            vaddr = rva_base + u64(section.virtual_address),
            bytes = section_data[:section_size]
        }
        append(&generic_sections, generic_section)
    }
    // Find .pdata and .text sections
    pdata: []pe.Runtime_Function = nil
    text_section := Section {}
    for section in generic_sections {
        if section.name == ".pdata" {
            pdata = slice.reinterpret(type_of(pdata), section.bytes)
        } else if section.name == ".text" {
            text_section = section
        }
    }
    if text_section.bytes == nil {
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
    symbol_idx := 0
    for symbol_idx < n_symbols {
        symbol := &symbols[symbol_idx]
        defer {
            symbol_idx += 1+int(symbol.number_of_aux_symbols)
        }
        // TODO(flysand): The code for reading the name from the symbol table might
        // get extracted into a separate procedure.
        nul_terminator_pos := 8
        symbol_name_arr := symbol.name
        for c, i in transmute([]u8) symbol_name_arr[:] {
            if c == 0 {
                nul_terminator_pos = i
                break
            }
        }
        symbol_name := transmute(string) symbol_name_arr[:nul_terminator_pos]
        if symbol.name_ref.zeroes == 0 {
            strtab_idx := int(symbol.name_ref.offset)
            if strtab_idx >= strtab_sz {
                return {}, false
            }
            // TODO(flysand): Potential OOB on seeking for NUL-terminator.
            symbol_name = cast(string) transmute(cstring) &strtab[strtab_idx]
        }
        if symbol.type == .DTYPE_FUNCTION {
            pdata_rec, pdata_ok := pdata_find_record(pdata, symbol.value)
            if !pdata_ok {
                // TODO(flysand): If entry in .pdata wasn't found we have no choice but calculate
                // the function boundaries using other symbols' adresses and known holes in .pdata
                // However I think the algorithm for this is a bit too complicated
                // so I will not implement this for now.
                continue
            }
            function_offset := u64(pdata_rec.begin_addr)
            function_size := u64(pdata_rec.end_addr - pdata_rec.begin_addr)
            generic_symbol := Symbol {
                name = symbol_name,
                section_no = int(symbol.section_number),
                vaddr = rva_base + u64(symbol.value),
                bytes = text_section.bytes[function_offset:function_offset+function_size]
            }
            append(&generic_symbols, generic_symbol)
        }
    }
    return File {
        format = .COFF,
        machine = generic_machine,
        sections = generic_sections[:],
        symbol = generic_symbols[:],
        type = .Relocatable,
    }, true
}
