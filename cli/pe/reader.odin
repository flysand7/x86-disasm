package pe

is_pe :: proc(file_contents: []u8) -> bool {
    bytes := transmute([^]u8) raw_data(file_contents)
    if len(file_contents) < PE_SIGNATURE_OFFSET + size_of(u32) {
        return false
    }
    magic_offset := (transmute(^u32le) &bytes[PE_SIGNATURE_OFFSET])^
    if len(file_contents) < int(magic_offset) + size_of(u32) {
        return false
    }
    header_magic := (transmute(^u32le) &bytes[magic_offset])^
    if header_magic != PE_SIGNATURE {
        return false
    }
    if len(file_contents) < int(magic_offset) + size_of(u32) + size_of(File_Header) {
        return false
    }
    file_header := (transmute(^File_Header) &bytes[magic_offset + size_of(u32)])^
    if !(file_header.machine == .AMD64 || file_header.machine == .I386) {
        return false
    }
    return true
}

is_coff :: proc(file_contents: []u8) -> bool {
    bytes := transmute([^]u8) raw_data(file_contents)
    if len(file_contents) < size_of(File_Header) {
        return false
    }
    file_header := transmute(^File_Header) bytes
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

pe_machine_bitness :: proc(file_contents: []u8) -> int {
    bytes := transmute([^]u8) raw_data(file_contents)
    magic_offset := (transmute(^u32le) &bytes[PE_SIGNATURE_OFFSET])^
    header := (transmute(^File_Header) &bytes[magic_offset + size_of(u32)])^
    #partial switch header.machine {
    case .AMD64: return 64
    case .I386:  return 32
    case: unreachable()
    }
}

coff_machine_bitness :: proc(file_contents: []u8) -> int {
    bytes := transmute([^]u8) raw_data(file_contents)
    header := transmute(^File_Header) bytes
    #partial switch header.machine {
    case .AMD64: return 64
    case .I386:  return 32
    case: unreachable()
    }
}