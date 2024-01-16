package disasm

import "core:io"
import "core:fmt"

inst_print_intel :: proc "contextless" (s: ^Stream, inst: Inst, colors := true) {
    if colors {
        stream_write_str(s, COLOR_R)
    }
    if .Lock in inst.flags {
        stream_write_str(s, "lock ")
    }
    if .Rep in inst.flags {
        stream_write_str(s, "rep ")
    } else if .Repnz in inst.flags {
        stream_write_str(s, "repnz ")
    } else if .Repz in inst.flags {
        stream_write_str(s, "repz ")
    }
    stream_write_str(s, inst.mnemonic)
    if colors {
        stream_write_str(s, COLOR_RESET)
    }
    for i in 0 ..< inst.op_count {
        stream_write_str(s, i != 0? ", " : " ")
        operand := inst.op[i]
        switch op in operand {
            case Mem_Short:
                print_color_string(s, COLOR_Y, "short ", colors)
                print_color_int(s, COLOR_B, cast(i64) op.disp, true, colors)
            case Mem_Near:
                print_color_string(s, COLOR_Y, mem_size_name(op.size), colors)
                stream_write_str(s, " [")
                print_color_int(s, COLOR_B, cast(i64) op.offs, true, colors)
                stream_write_str(s, "]")
            case Mem_Far:
                fmt_int(s, op.seg, false)
                stream_write_str(s, ":[")
                print_color_int(s, COLOR_B, cast(i64) op.offs, true, colors)
                stream_write_str(s, "]")
            case Mem:
                print_color_string(s, COLOR_Y, mem_size_name(op.size), colors)
                if reg_present(inst.seg) {
                    stream_write_str(s, reg_name(inst.seg))
                    stream_write_str(s, ":")
                }
                stream_write_str(s, "[")
                has_before := false
                if reg_present(op.base) {
                    print_color_string(s, COLOR_G, reg_name(op.base), colors)
                    has_before = true
                }
                if reg_present(op.index) {
                    stream_write_str(s, has_before?"+":"")
                    stream_write_int(s, op.scale, false)
                    stream_write_str(s, "*")
                    print_color_string(s, COLOR_G, reg_name(op.index), colors)
                }
                if op.disp != 0 {
                    print_color_int(s, COLOR_B, cast(i64) op.disp, true, colors)
                }
                stream_write_str(s, "]")
            case Reg: print_color_string(s, COLOR_G, reg_name(op), colors)
            case Imm: print_color_int(s, COLOR_B, op.value, true, colors)
        }
    }
    stream_write_str(s, "\n")
}
