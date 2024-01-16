package disasm

import "core:c"
import "table"

@(export, private="file", link_name="x86_disasm_pre_decode")
export_pre_decode :: proc "c" (
    cpu_mode: CPU_Mode,
    buf_len: c.size_t,
    buf: [^]u8,
    out_encoding: ^u64,
    out_size: ^u64,
) -> Error {
    inst_len, encoding, error := pre_decode(cpu_mode, buf[:buf_len])
    out_encoding^ = transmute(u64) encoding
    out_size^ = cast(u64) inst_len
    return error
}

@(export, private="file", link_name="x86_disasm_decode")
export_decode :: proc "c" (
    cpu_mode: CPU_Mode,
    buf_len: c.size_t,
    buf: [^]u8,
    encoding: u64,
    out_instruction: ^Inst,
) -> c.bool {
    inst, ok := decode(cpu_mode, buf[:buf_len], transmute(table.Encoding) encoding)
    out_instruction^ = inst
    return ok
}

@(export, private="file", link_name="x86_stream_flush")
export_stream_flush :: proc "c" (s: ^Stream) {
    stream_flush(s)
}

@(export, private="file", link_name="x86_stream_write_str")
export_stream_write_str :: proc "c" (s: ^Stream, str_length: int, str: [^]u8) {
    stream_write_str(s, transmute(string) str[:str_length])
}

@(export, private="file", link_name="x86_stream_write_int")
export_stream_write_int :: proc "c" (s: ^Stream, i: i64, force_sign: b32) {
    stream_write_int(s, i, cast(bool) force_sign)
}

@(export, private="file", link_name="x86_stream_write_hex")
export_stream_write_hex :: proc "c" (s: ^Stream, i: i64, pad: int) {
    stream_write_hex(s, i, pad)
}

@(export, private="file", link_name="x86_stream_write_inst_intel")
export_inst_print_intel :: proc "c" (s: ^Stream, inst: ^Inst, colors: b32) {
    inst_print_intel(s, inst^, cast(bool) colors)
}

@(export, private="file", link_name="x86_stream_write_inst_att")
inst_print_att :: proc "c" (s: ^Stream, inst: ^Inst, colors: b32) {
    inst_print_intel(s, inst^, cast(bool) colors)
}
