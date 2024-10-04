package arg_parse

import "core:strings"
import "core:fmt"
import "core:os"

/*
Parsed value of a command-line option.
*/
Option_Value :: union {
    string,
    Key_Value,
}

/*
Key-value pair as the option value.
*/
Key_Value :: struct {
    key: string,
    value: string,
}

@(private)
parse_option :: proc(arg_str: string) -> (string, Option_Value) {
    assert(arg_str[0] == '-', "Option must begin with a '-' sign")
    arg_str := arg_str[1:]
    colon_pos := strings.index_byte(arg_str, ':')
    if colon_pos == -1 {
        return arg_str, nil
    }
    option_name := arg_str[:colon_pos]
    key_value := arg_str[colon_pos+1:]
    equals_pos := strings.index_byte(key_value, '=')
    if equals_pos == -1 {
        return option_name, key_value
    }
    key := key_value[:equals_pos]
    value := key_value[equals_pos+1:]
    return option_name, Key_Value { key, value }
}

parse :: proc(arg_strs: []string, allocator := context.allocator) -> ([]string, map[string]Option_Value) {
    args := make([dynamic]string, allocator = allocator)
    options := make(map[string]Option_Value, allocator = allocator)
    for arg_str in arg_strs {
        if arg_str[0] != '-' {
            append(&args, arg_str)
            continue
        }
        option_name, option_value := parse_option(arg_str)
        options[option_name] = option_value
    }
    return args[:], options
}
