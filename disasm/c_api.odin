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
export_decode :: proc(
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
