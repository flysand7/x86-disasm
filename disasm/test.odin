package disasm

import "core:os"
import "core:fmt"
import "core:testing"
import "core:strings"

@(test, private)
test_dump :: proc(t: ^testing.T) {
    for arg in os.args[1:] {
        fmt.println("----------")
        file_bytes, file_bytes_ok := os.read_entire_file(arg)
        testing.expect_value(t, file_bytes_ok, true)
        dump_bytes(file_bytes)
    }
}

@(test, private)
test_disasm :: proc(t: ^testing.T) {
    for arg in os.args[1:] {
        fmt.println("----------")
        file_bytes, file_bytes_ok := os.read_entire_file(arg)
        testing.expect_value(t, file_bytes_ok, true)
        ctx := create_ctx(file_bytes)
        builder := strings.builder_make()
        writer  := strings.to_writer(&builder)
        for inst in disasm_inst(&ctx) {
            print_inst(inst, writer)
        }
        fmt.println(strings.to_string(builder))
        if ctx.offset < len(ctx.bytes) {
            fmt.printf("Error disassembling the byte: %02x\n", ctx.bytes[ctx.offset])
            testing.fail_now(t)
        }
    }
}

import "table"

@(test, private)
test_verify_tables :: proc(t: ^testing.T) {
    fail_count := 0
    next_row: for enc1, idx1 in table.encodings {
        for enc2, idx2 in table.encodings {
            if idx1 <= idx2 {
                continue next_row
            }
            if encodings_intersect(enc1, enc2) {
                fail_count += 1
                if fail_count < 10 {
                    fmt.eprintf("Found intersecting encodings:\n")
                    fmt.eprintf("  %s (%.*b)\n", enc1.mnemonic, enc1.opcode.count, enc1.opcode.value)
                    fmt.eprintf("  %s (%.*b)\n", enc2.mnemonic, enc2.opcode.count, enc2.opcode.value)
                    testing.fail(t)
                }
            }
        }
    }
    fmt.printf("Total mismatches: %d\n", fail_count)
}

@(private)
encodings_intersect :: proc(enc1, enc2: table.Encoding) -> bool {
    // Filter out opcodes with prefixes that don't intersect.
    if (.Flag_Np in enc1.flags) {
        if .Flag_F2 in enc2.flags || .Flag_F3 in enc2.flags || .Flag_Dp in enc2.flags {
            return false
        }
    }
    if (.Flag_Np in enc2.flags) {
        if .Flag_F2 in enc1.flags || .Flag_F3 in enc1.flags || .Flag_Dp in enc1.flags {
            return false
        }
    }
    if (.Flag_Vw0 in enc1.flags && .Flag_Vw1 in enc2.flags || .Flag_Vw0 in enc2.flags && .Flag_Vw1 in enc1.flags) {
        return false
    }
    if (.Flag_Vp in enc1.flags) != (.Flag_Vp in enc2.flags) {
        return false
    }
    if (.Flag_0f in enc1.flags) != (.Flag_0f in enc2.flags) {
        return false
    }
    if (.Flag_F2 in enc1.flags) != (.Flag_F2 in enc2.flags) {
        return false
    }
    if (.Flag_F3 in enc1.flags) != (.Flag_F3 in enc2.flags) {
        return false
    }
    if (.Flag_38 in enc1.flags) != (.Flag_38 in enc2.flags) {
        return false
    }
    if (.Flag_3a in enc1.flags) != (.Flag_3a in enc2.flags) {
        return false
    }
    if (.Flag_Dp in enc1.flags) != (.Flag_Dp in enc2.flags) {
        return false
    }
    // We're gonna go lazy about this checking.
    // We'll construct masks for every byte of the encoding.
    // literal bits will have mask 1 and value equal to the bits
    // ignored bits will have mask 0 and value of 0 (everything matches)
    // fields are going to be treated as ignored for now, we'll have to
    // special case a bunch.
    masks1 := make([dynamic]u8)
    bytes1 := make([dynamic]u8)
    masks2 := make([dynamic]u8)
    bytes2 := make([dynamic]u8)
    cur_o := u8(8)
    cur_m := u8(0)
    cur_b := u8(0)
    for mask in encoding_masks(enc1) {
        switch m in mask {
            case table.Bits:
                cur_o -= m.count
                cur_b |= m.value << cur_o
                cur_m |= (1<<m.count - 1) << cur_o
            case table.Field:
                width := table.field_widths[m]
                cur_o -= width
                if m == .Mod11 {
                    cur_b |= 0b11000000
                    cur_m |= 0b11000000
                }
            case table.Ign:
                cur_o -= m.count
            case: unreachable()
        }
        if cur_o == 0 {
            append(&masks1, cur_m)
            append(&bytes1, cur_b)
            cur_m = 0
            cur_b = 0
            cur_o = 8
        }
    }
    assert(cur_o == 8, enc1.mnemonic)
    cur_o = 8
    cur_m = 0
    cur_b = 0
    for mask in encoding_masks(enc2) {
        switch m in mask {
            case table.Bits:
                cur_o -= m.count
                cur_b |= m.value << cur_o
                cur_m |= (1<<m.count - 1) << cur_o
            case table.Field:
                width := table.field_widths[m]
                cur_o -= width
                if m == .Mod11 {
                    cur_b |= 0b11000000
                    cur_m |= 0b11000000
                }
            case table.Ign:
                cur_o -= m.count
            case: unreachable()
        }
        if cur_o == 0 {
            append(&masks2, cur_m)
            append(&bytes2, cur_b)
            cur_m = 0
            cur_b = 0
            cur_o = 8
        }
    }
    assert(cur_o == 8, enc2.mnemonic)
    // fmt.println("---")
    // for b in bytes1 do fmt.printf("%08b ", b)
    // fmt.println()
    // for b in bytes2 do fmt.printf("%08b ", b)
    // fmt.println()
    // for b in masks1 do fmt.printf("%08b ", b)
    // fmt.println()
    // for b in bytes2 do fmt.printf("%08b ", b)
    // fmt.println()
    for i in 0 ..< min(len(bytes1), len(bytes2)) {
        b1 := bytes1[i]
        b2 := bytes2[i]
        m1 := masks1[i]
        m2 := masks2[i]
        if b1 & m1 != b2 & m2 {
            return false
        }
    }
    return true
}

@(private)
encoding_masks :: proc(encoding: table.Encoding) -> ([]table.Bit_Mask) {
    masks := make([dynamic]table.Bit_Mask, context.temp_allocator)
    append(&masks, encoding.opcode)
    for m in encoding.masks {
        append(&masks, m)
    }
    return masks[:]
}

@(private)
mask_len :: proc(m: table.Bit_Mask) -> int {
    switch mask in m {
        case table.Bits:
            return cast(int) mask.count
        case table.Field:
            return cast(int) table.field_widths[mask]
        case table.Ign:
            return cast(int) mask.count
        case: unreachable()
    }
}
