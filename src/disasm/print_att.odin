package x86_disasm

import "core:io"

print_att :: proc(w: io.Writer, addr: u64, inst: Instruction) -> io.Error {
    return .None
}