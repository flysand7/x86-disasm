package disasm

import "core:runtime"
import "core:os"
import "core:mem"

BUF_SIZE :: 1024

Stream_Proc :: #type proc "c" (ctx: rawptr, buf_len: int, buf: [^]u8)

Stream :: struct {
	procedure: Stream_Proc,
	data:      rawptr,
    _buf:      [BUF_SIZE]u8,
    _bufi:     int,
}

make_stdout_stream :: proc "contextless" () -> Stream {
    stdout_print_proc :: proc "c" (ctx: rawptr, buf_len: int, buf: [^]u8) {
        context = runtime.default_context()
        file := cast(os.Handle) cast(uintptr) os.stdout
        os.write(file, buf[:buf_len])
    }
    return {
        data = cast(rawptr) cast(uintptr) os.stdout,
        procedure = stdout_print_proc,
        _buf = {},
        _bufi = 0,
    }
}

stream_flush :: proc "contextless" (s: ^Stream) {
    if s._bufi > 0 {
        s.procedure(s.data, s._bufi, &s._buf[0])
        s._bufi = 0
    }
}

stream_write_str :: proc "contextless" (s: ^Stream, str: string) {
    if len(str) > BUF_SIZE {
        stream_flush(s)
        s.procedure(s.data, len(str), raw_data(str))
    } else if s._bufi + len(str) > BUF_SIZE {
        stream_flush(s)
    }
    mem.copy(raw_data(s._buf[s._bufi:]), raw_data(str), len(str))
    s._bufi += len(str)
}

stream_write_int :: proc "contextless" (s: ^Stream, #any_int i: i64, force_sign: bool) {
    buf := [32]u8 {}
    bufi := len(buf)
    i := i
    do_sign := force_sign
    negative := false
    if i < 0 {
        do_sign = true
        negative = true
        i = -i
    }
    for condition := true; condition; condition = i != 0 {
        bufi -= 1
        buf[bufi] = cast(u8)(i%10) + '0'
        i /= 10
    }
    if do_sign {
        bufi -= 1
        buf[bufi] = negative? '-' : '+'
    }
    stream_write_str(s, transmute(string) buf[bufi:])
}

stream_write_hex :: proc "contextless" (s: ^Stream, #any_int i: i64, pad: int) {
    hex := "0123456789abcdef    "
    buf := [20]u8 {}
    bufi := len(buf)
    i := i
    for condition := true; condition; condition = i != 0 {
        bufi -= 1
        buf[bufi] = hex[i%16]
        i /= 16
    }
    for len(buf) - bufi < pad {
        bufi -= 1
        buf[bufi] = '0'
    }
    stream_write_str(s, transmute(string) buf[bufi:])
}
