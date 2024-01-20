#!/usr/bin/env python

import struct

with open('tests/is-even.bin', 'wb') as file:
    file.write(b"\x31\xC0")
    for i in range(2**20):
        ib = struct.pack("<I", i)
        file.write(b"\x81\xF9" + ib)
        if i%2 == 0:
            file.write(b"\x75\x03")
            file.write(b"\xFF\xC0")
            file.write(b"\xC3")
        else:
            file.write(b"\x75\x01")
            file.write(b"\xC3")

    file.write(b"\xC3")
