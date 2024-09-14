package cli

import "core:strings"

Key_Value :: struct {
    key: string,
    value: string,
}

Arg_Value :: union {
    string,
    Key_Value,
}

parse_args :: proc(args_str: []string) -> (args: [dynamic]string, options: map[string]Arg_Value) {
    args = make([dynamic]string, allocator = context.allocator)
    options = make(map[string]Arg_Value, allocator = context.allocator)
    for arg_str in args_str {
        if arg_str[0] != '-' {
            append(&args, arg_str)
            continue
        }
        arg_str := arg_str[1:]
        colon_pos := strings.index_byte(arg_str, ':')
        if colon_pos == -1 {
            options[arg_str] = nil
            continue
        }
        option_name := arg_str[:colon_pos]
        key_value := arg_str[colon_pos+1:]
        equals_pos := strings.index_byte(key_value, '=')
        if equals_pos == -1 {
            options[option_name] = key_value
            continue
        }
        key := key_value[:equals_pos]
        value := key_value[equals_pos+1:]
        options[option_name] = Key_Value { key, value }
    }
    return args, options
}
