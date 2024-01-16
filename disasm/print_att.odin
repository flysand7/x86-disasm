package disasm

import "core:io"
import "core:fmt"

inst_print_att :: proc "contextless" (s: ^Stream, inst: Inst, colors := true) {
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
    i := 0
    needs_data_suffix := true
    instruction_operands := inst.op
    for operand in instruction_operands[:inst.op_count] {
        if reg, ok := operand.(Reg); ok {
            needs_data_suffix = false
        }
    }
    #reverse for operand in instruction_operands[:inst.op_count] {
        stream_write_str(s, i != 0? ", " : " ")
        switch op in operand {
            case Mem_Short:
                print_color_string(s, COLOR_Y, "short ", colors)
                print_color_int(s, COLOR_B, cast(i64) op.disp, false, colors)
            case Mem_Near:
                print_color_string(s, COLOR_Y, mem_size_name(op.size), colors)
                stream_write_str(s, " *")
                print_color_int(s, COLOR_B, cast(i64) op.offs, false, colors)
            case Mem_Far:
                stream_write_int(s, op.seg, false)
                stream_write_str(s, ":")
                print_color_int(s, COLOR_B, cast(i64) op.offs, false, colors)
            case Mem:
                if needs_data_suffix {
                    print_color_string(s, COLOR_Y, mem_size_name(op.size), colors)
                }
                if reg_present(inst.seg) {
                    stream_write_str(s, "%")
                    stream_write_str(s, reg_name(inst.seg))
                }
                if op.disp != 0 {
                    stream_write_str(s, "$")
                    print_color_int(s, COLOR_B, cast(i64) op.disp, false, colors)
                }
                stream_write_str(s, "(")
                has_before := false
                if reg_present(op.base) {
                    stream_write_str(s, "%")
                    print_color_string(s, COLOR_G, reg_name(op.base), colors)
                    has_before = true
                }
                if reg_present(op.index) {
                    stream_write_str(s, ",")
                    print_color_string(s, COLOR_G, reg_name(op.index), colors)
                    stream_write_str(s, ",")
                    stream_write_int(s, op.scale, false)
                }
                stream_write_str(s, ")")
            case Reg:
                stream_write_str(s, "%")
                print_color_string(s, COLOR_G, reg_name(op), colors)
            case Imm:
                stream_write_str(s, "$")
                print_color_int(s, COLOR_B, op.value, false, colors)
        }
        i += 1
    }
    stream_write_str(s, "\n")
}
