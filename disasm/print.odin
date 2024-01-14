package disasm

import "core:fmt"
import "core:io"
import "table"
import "generated_table"

COLOR_RESET :: "\e[0m"
COLOR_R :: "\e[38;5;210m"
COLOR_G :: "\e[38;5;114m"
COLOR_B :: "\e[38;5;105m"
COLOR_GREY :: "\e[38;5;242m"

@(private)
fmt_int :: proc(w: io.Writer, #any_int hex: i64) {
    sign_ch := '+'
    hex_abs := hex
    if hex < 0 {
        sign_ch = '-'
        hex_abs = -hex
    }
    if hex_abs < 10 {
        fmt.wprintf(w, "%c%d", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u8) {
        fmt.wprintf(w, "%c0x%02x", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u16) {
        fmt.wprintf(w, "%c0x%04x", sign_ch, hex_abs)
    } else if hex_abs <= auto_cast max(u32) {
        fmt.wprintf(w, "%c0x%08x", sign_ch, hex_abs)
    } else {
        fmt.wprintf(w, "%c0x%016x", sign_ch, hex_abs)
    }
}

encoding_print :: proc(e: table.Encoding) {
    fmt.println("Encoding {")
    if .Is_Slice in table.encoding_flags(e) {
        fmt.printf("\tslice_idx: %#04x\n", table.encoding_slice_index(e))
        fmt.println("\textra op:", table.encoding_extra_op(e))
        fmt.println("\tflags:", table.encoding_flags(e))
        fmt.println("\tmod kind:", table.encoding_mod_kind(e))
    } else {
        fmt.println("\tdata override:", table.encoding_data_override(e))
        fmt.println("\textra op:", table.encoding_extra_op(e))
        fmt.println("\tflags:", table.encoding_flags(e))
        fmt.println("\tmnemonic:", generated_table.string_table[table.encoding_mnemonic_idx(e)])
        fmt.println("\tmod kind:", table.encoding_mod_kind(e))
        fmt.println(
            "\trm size:", table.encoding_rm_size(e, 0b00, .Default),
            "rx type:", table.encoding_rm_type(e),
        )
        fmt.println(
            "\trx size:", table.encoding_rx_size(e, .Default),
            "rx type:", table.encoding_rx_type(e),
            "rx idx:", table.encoding_rx(e),
        )
    }
    fmt.println("}")
}

reg_name :: proc(r: Reg) -> string {
    name := reg_names[r.kind][r.size][r.idx]
    if len(name) == 0 {
        return "(bad reg)"
    }
    return name
}

mem_size_name :: proc(s: Size) -> string {
    return mem_sizes[s]
}

print_color_string :: proc(w: io.Writer, color: string, str: string, colors: bool) {
    if colors {
        fmt.wprint(w, color, sep="")
    }
    fmt.wprintf(w, "%s", str)
    if colors {
        fmt.wprint(w, COLOR_RESET, sep="")
    }
}

print_color_int :: proc(w: io.Writer, color: string, str: i64, colors: bool) {
    if colors {
        fmt.wprint(w, color, sep="")
    }
    fmt_int(w, str)
    if colors {
        fmt.wprint(w, COLOR_RESET, sep="")
    }
}

@(private="file")
mem_sizes := [Size]string {
    .Default  = "*bad size*",
    .Size_8   = "byte",
    .Size_16  = "word",
    .Size_32  = "dword",
    .Size_64  = "qword",
    .Size_128 = "xmmword",
    .Size_256 = "ymmword",
    .Size_512 = "zmmword",
}

@(private="file")
reg_names := [Reg_Set][Size][16]string {
    .Reg = {
        .Default  = {},
        .Size_128 = {},
        .Size_256 = {},
        .Size_512 = {},
        .Size_8   = {
            "al",
            "cl",
            "dl",
            "bl",
            "ah",
            "ch",
            "dh",
            "bh",
            "r8b",
            "r9b",
            "r10b",
            "r11b",
            "r12b",
            "r13b",
            "r14b",
            "r15b",
        },
        .Size_16  = {
            "ax",
            "cx",
            "dx",
            "bx",
            "si",
            "di",
            "sp",
            "bp",
            "r8w",
            "r9w",
            "r10w",
            "r11w",
            "r12w",
            "r13w",
            "r14w",
            "r15w",
        },
        .Size_32  = {
            "eax",
            "ecx",
            "edx",
            "ebx",
            "esi",
            "edi",
            "esp",
            "ebp",
            "r8d",
            "r9d",
            "r10d",
            "r11d",
            "r12d",
            "r13d",
            "r14d",
            "r15d",
        },
        .Size_64  = {
            "rax",
            "rcx",
            "rdx",
            "rbx",
            "rsi",
            "rdi",
            "rsp",
            "rbp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
        },
    },
    .Mmx = {
        .Default = {},
        .Size_8 = {},
        .Size_16 = {},
        .Size_32 = {},
        .Size_64 = {
            0 = "mm0",
            1 = "mm1",
            2 = "mm2",
            3 = "mm3",
            4 = "mm4",
            5 = "mm5",
            6 = "mm6",
            7 = "mm7",
        },
        .Size_128 = {},
        .Size_256 = {},
        .Size_512 = {},
    },
    .Xmm = {
        .Default = {},
        .Size_8 = {},
        .Size_16 = {
            "xmm0",
            "xmm1",
            "xmm2",
            "xmm3",
            "xmm4",
            "xmm5",
            "xmm6",
            "xmm7",
            "xmm8",
            "xmm9",
            "xmm10",
            "xmm11",
            "xmm12",
            "xmm13",
            "xmm14",
            "xmm15",
        },
        .Size_32 = {
            "xmm0",
            "xmm1",
            "xmm2",
            "xmm3",
            "xmm4",
            "xmm5",
            "xmm6",
            "xmm7",
            "xmm8",
            "xmm9",
            "xmm10",
            "xmm11",
            "xmm12",
            "xmm13",
            "xmm14",
            "xmm15",
        },
        .Size_64 = {
            "xmm0",
            "xmm1",
            "xmm2",
            "xmm3",
            "xmm4",
            "xmm5",
            "xmm6",
            "xmm7",
            "xmm8",
            "xmm9",
            "xmm10",
            "xmm11",
            "xmm12",
            "xmm13",
            "xmm14",
            "xmm15",
        },
        .Size_128 = {
            "xmm0",
            "xmm1",
            "xmm2",
            "xmm3",
            "xmm4",
            "xmm5",
            "xmm6",
            "xmm7",
            "xmm8",
            "xmm9",
            "xmm10",
            "xmm11",
            "xmm12",
            "xmm13",
            "xmm14",
            "xmm15",
        },
        .Size_256 = {
            "ymm0",
            "ymm1",
            "ymm2",
            "ymm3",
            "ymm4",
            "ymm5",
            "ymm6",
            "ymm7",
            "ymm8",
            "ymm9",
            "ymm10",
            "ymm11",
            "ymm12",
            "ymm13",
            "ymm14",
            "ymm15",
        },
        .Size_512 = {},
    },
    .Sreg = {
        .Default = {},
        .Size_8 = {},
        .Size_32 = {},
        .Size_64 = {},
        .Size_128 = {},
        .Size_256 = {},
        .Size_512 = {},
        .Size_16 = {
            0 = "es",
            1 = "cs",
            2 = "ss",
            3 = "ds",
            4 = "fs",
            5 = "gs",
        },
    },
    .Dreg = {
        .Default = {},
        .Size_8 = {},
        .Size_32 = {},
        .Size_64 = {},
        .Size_128 = {},
        .Size_256 = {},
        .Size_512 = {},
        .Size_16 = {
            0 = "dr0",
            1 = "dr1",
            2 = "dr2",
            3 = "dr3",
            4 = "dr4",
            5 = "dr5",
            6 = "dr6",
            7 = "dr7",
        },
    },
    .Creg = {
        .Default = {},
        .Size_8 = {},
        .Size_16 = {},
        .Size_64 = {},
        .Size_128 = {},
        .Size_256 = {},
        .Size_512 = {},
        .Size_32 = {
            0 = "cr0",
            1 = "cr1",
            2 = "cr2",
            3 = "cr3",
            4 = "cr4",
            5 = "cr5",
            6 = "cr6",
            7 = "cr7",
        },
    },
    .Bndreg = {
        .Default = {},
        .Size_8 = {},
        .Size_16 = {},
        .Size_64 = {},
        .Size_128 = {},
        .Size_256 = {},
        .Size_512 = {},
        .Size_32 = {
            0 = "bnd0",
            1 = "bnd1",
            2 = "bnd2",
            3 = "bnd3",
            4 = "bnd4",
            5 = "bnd5",
            6 = "bnd6",
            7 = "bnd7",
        },
        
    },
    .St = {
        .Default = {},
        .Size_8 = {},
        .Size_16 = {},
        .Size_32 = {},
        .Size_128 = {},
        .Size_256 = {},
        .Size_512 = {},
        .Size_64 = {
            0 = "st(0)",
            1 = "st(1)",
            2 = "st(2)",
            3 = "st(3)",
            4 = "st(4)",
            5 = "st(5)",
            6 = "st(6)",
            7 = "st(7)",
        },
    },
    .Extras = {
        .Default = {},
        .Size_128 = {},
        .Size_256 = {},
        .Size_512 = {},
        .Size_8 = {},
        .Size_16 = {
            0 = "ip",
            1 = "flags",
        },
        .Size_32 = {
            0 = "eip",
            1 = "eflags",
        },
        .Size_64 = {
            0 = "rip",
            1 = "rflags",
        },
    },
}
