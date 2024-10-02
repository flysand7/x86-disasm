#+private
package table

is_oct_digit :: proc(d: u8) -> bool {
    return '0' <= d && d <= '7'
}

is_digit :: proc(d: u8) -> bool {
    return '0' <= d && d <= '9'
}

from_digit :: proc(d: u8) -> u8 {
    return d - '0'
}

