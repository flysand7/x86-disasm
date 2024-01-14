package disasm

import "core:io"
import "core:fmt"

inst_print_intel :: proc(inst: Inst, w: io.Writer, colors := true) {
    if colors {
        fmt.wprint(w, COLOR_R, sep="")
    }
    if .Lock in inst.flags {
        fmt.wprintf(w, "lock ")
    }
    if .Rep in inst.flags {
        fmt.wprintf(w, "rep ")
    } else if .Repnz in inst.flags {
        fmt.wprintf(w, "repnz ")
    } else if .Repz in inst.flags {
        fmt.wprintf(w, "repz ")
    }
    fmt.wprintf(w, "%s", inst.mnemonic)
    if colors {
        fmt.wprint(w, COLOR_RESET, sep="")
    }
    for i in 0 ..< inst.op_count {
        fmt.wprintf(w, i != 0? ", " : " ")
        operand := inst.op[i]
        switch op in operand {
            case Mem_Short:
                fmt.wprintf(w, "short ")
                fmt_int(w, op.disp)
            case Mem_Near:
                fmt.wprintf(w, "%s [", mem_size_name(op.size))
                fmt_int(w, op.offs)
                fmt.wprintf(w, "]")
            case Mem_Far:
                fmt_int(w, op.seg)
                fmt.wprintf(w, ":[")
                fmt_int(w, op.offs)
                fmt.wprintf(w, "]")
            case Mem:
                fmt.wprintf(w, "%s ", mem_size_name(op.size))
                if reg_present(inst.seg) {
                    fmt.wprintf(w, "%s:", reg_name(inst.seg))
                }
                fmt.wprintf(w, "[")
                has_before := false
                if reg_present(op.base) {
                    print_color_string(w, COLOR_G, reg_name(op.base), colors)
                    has_before = true
                }
                if reg_present(op.index) {
                    fmt.wprintf(w, "%s%d*", has_before?"+":"", op.scale)
                    print_color_string(w, COLOR_G, reg_name(op.index), colors)
                }
                if op.disp != 0 {
                    fmt_int(w, op.disp)
                }
                fmt.wprintf(w, "]")
            case Reg:      print_color_string(w, COLOR_G, reg_name(op), colors)
            case Imm:      print_color_int(w, COLOR_B, op.value, colors)
        }
    }
    fmt.wprintf(w, "\n")
}
