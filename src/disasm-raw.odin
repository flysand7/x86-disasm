package disasm_cli

import "disasm"

import "core:fmt"
import "core:strings"

disasm_hex :: proc(ctx: ^Ctx, hex: []u8) {
    hexof :: proc(a: u8) -> (u8, bool) {
        if '0' <= a && a <= '9' {
            return a-'0',true
        } else if 'a' <= a && a <= 'f' {
            return a-'a'+10,true
        } else if 'A' <= a && a <= 'F' {
            return a-'A'+10,true
        }
        return {}, false
    }
    bytes := make([dynamic]u8)
    for i := 0; i < len(hex); i += 1 {
        if h0, ok := hexof(hex[i]); ok {
            if i == len(hex) {
                break
            }
            i += 1
            if h1, ok := hexof(hex[i]); ok {
                append(&bytes, h0<<4|h1)
            }
        }
    }
    disasm_raw(ctx, bytes[:])
}

disasm_raw :: proc(ctx: ^Ctx, bytes: []u8) {
    if !ctx.print_all {
        builder := strings.builder_make()
        stream := stream_from_builder(&builder)
        disasm_print_bytes(ctx, &stream, 0, bytes)
        fmt.println(strings.to_string(builder))
    } else {
        stream := disasm.make_stdout_stream()
        disasm_print_bytes(ctx, &stream, 0, bytes)
    }
}

