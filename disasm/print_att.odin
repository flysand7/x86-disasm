package disasm

import "core:io"
import "core:fmt"

inst_print_att :: proc(inst: Inst, w: io.Writer, colors := true) {
    if colors {
        fmt.wprint(w, COLOR_R, sep="")
    }
    if .Lock in inst.flags {
        fmt.wprint(w, "lock ")
    }
    if .Rep in inst.flags {
        fmt.wprint(w, "rep ")
    } else if .Repnz in inst.flags {
        fmt.wprint(w, "repnz ")
    } else if .Repz in inst.flags {
        fmt.wprint(w, "repz ")
    }
    fmt.wprint(w, inst.mnemonic)
    if colors {
        fmt.wprint(w, COLOR_RESET)
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
        fmt.wprint(w, i != 0? ", " : " ")
        switch op in operand {
            case Mem_Short:
                fmt.wprint(w, COLOR_Y+"short "+COLOR_RESET)
                print_color_int(w, COLOR_B, cast(i64) op.disp, false, colors)
            case Mem_Near:
                fmt.wprintf(w, COLOR_Y+"%s"+COLOR_RESET+" *", mem_size_name(op.size))
                print_color_int(w, COLOR_B, cast(i64) op.offs, false, colors)
            case Mem_Far:
                fmt_int(w, op.seg, false)
                fmt.wprint(w, ":")
                print_color_int(w, COLOR_B, cast(i64) op.offs, false, colors)
            case Mem:
                if needs_data_suffix {
                    fmt.wprintf(w, COLOR_Y+"%s "+COLOR_RESET, mem_size_name(op.size))
                }
                if reg_present(inst.seg) {
                    fmt.wprintf(w, "%%%s:", reg_name(inst.seg))
                }
                if op.disp != 0 {
                    fmt.wprint(w, "$")
                    print_color_int(w, COLOR_B, cast(i64) op.disp, false, colors)
                }
                fmt.wprintf(w, "(")
                has_before := false
                if reg_present(op.base) {
                    fmt.wprint(w, "%")
                    print_color_string(w, COLOR_G, reg_name(op.base), colors)
                    has_before = true
                }
                if reg_present(op.index) {
                    fmt.wprint(w, ",")
                    print_color_string(w, COLOR_G, reg_name(op.index), colors)
                    fmt.wprintf(w, ",%d", op.scale)
                }
                fmt.wprint(w, ")")
            case Reg:
                fmt.wprint(w, "%")
                print_color_string(w, COLOR_G, reg_name(op), colors)
            case Imm:
                fmt.wprint(w, "$")
                print_color_int(w, COLOR_B, op.value, false, colors)
        }
        i += 1
    }
    fmt.wprintf(w, "\n")
}
