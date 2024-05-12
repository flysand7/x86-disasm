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
    return true
}
