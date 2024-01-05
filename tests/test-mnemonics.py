#!/usr/bin/python

import sys
import subprocess
import string

OBJDUMP_CMD = [
    'objdump',
    '--disassembler-color=off',
    '-M intel',
    '-d',
    '-j', '.text',
]

OUR_CMD = [
    './x86-disasm',
    '-no-color',
    '-force-no-syms',
]

if len(sys.argv) < 2:
    print("Usage: test-mnemonics <file to test>")
    sys.exit(2)

filename = sys.argv[1]

objdump_cmd = OBJDUMP_CMD
objdump_cmd.append(filename)
objdump_process = subprocess.Popen(objdump_cmd, stdout=subprocess.PIPE)
if objdump_process.stdout is None:
    print("Failed to capture process stdout")
    sys.exit(1)

ref_lines: list[tuple[str,str]] = []
for line in objdump_process.stdout:
    line = line[:-1]
    line = line.replace(b'\t', b' ', -1)
    line = line.decode('utf-8')
    if not line.startswith('  '):
        continue
    if line.startswith('   '):
        continue
    colon_idx = line.index(':')
    address = line[2:colon_idx]
    bytes_start = colon_idx+1
    while line[bytes_start] == ' ':
        bytes_start += 1
    bytes_end = bytes_start
    label = False
    while True:
        if bytes_end+2 >= len(line):
            label = True
            break
        byte = line[bytes_end:bytes_end+2]
        if not all(c in string.hexdigits for c in byte):
            bytes_end -= 1
            break
        bytes_end += 3
    if label:
        continue
    instruction_idx = bytes_end
    while line[instruction_idx] == ' ':
        instruction_idx += 1
    instruction = line[instruction_idx:].split(' ')
    mnemonic: str|None = None
    for tok in instruction:
        if tok in ['rep', 'lock', 'bnd', 'cs', 'ds', 'ss', 'es', 'fs', 'gs', 'data16', 'data32']:
            continue
        mnemonic = tok
        break
    assert not(mnemonic is None)
    ref_lines.append((address, mnemonic))

our_cmd = OUR_CMD
our_cmd.append(filename)
p_our = subprocess.Popen(our_cmd, stdout=subprocess.PIPE)
if p_our.stdout is None:
    print("Failed to capture process stdout")
    sys.exit(1)
our_lines: list[tuple[str, str]] = []
for line in p_our.stdout:
    line = line.decode('utf-8')
    if not line.startswith('  '):
        continue
    line = list(filter(None, line.split(' ')))
    address = line[0].lstrip('0')
    bytes = line[1]
    mnemonic: str|None = None
    for tok in line[2:]:
        if tok in ['rep', 'lock', 'bnd']:
            continue
        mnemonic = tok
        break
    assert not(mnemonic is None)
    our_lines.append((address, mnemonic))
    
for (our_address, our_mnemonic), (ref_address, ref_mnemonic) in zip(our_lines, ref_lines):
    our_address = our_address.lower()
    ref_address = ref_address.lower()
    if our_address != ref_address:
        print(f'Objdump address {ref_address} != {our_address}')
        sys.exit(1)
    our_mnemonic = our_mnemonic.strip().lower()
    ref_mnemonic = ref_mnemonic.strip().lower()
    if our_mnemonic != ref_mnemonic:
        # Objdump disassembles "xchg ax, ax" as NOP, which is a valid
        # encoding of NOP, but different from what I do. Maybe I'll
        # change it later, but this is a trivial case.
        if ref_mnemonic == "nop" and our_mnemonic == "xchg":
            continue
        # Condition codes...
        if ref_mnemonic == "je" and our_mnemonic == "jz":
            continue
        if ref_mnemonic == "jne" and our_mnemonic == "jnz":
            continue
        if ref_mnemonic == "sete" and our_mnemonic == "setz":
            continue
        if ref_mnemonic == "setne" and our_mnemonic == "setnz":
            continue
        # Fat mov that takes 64-bit immediate. Don't care
        if ref_mnemonic == "movabs" and our_mnemonic == "mov":
            continue
        print(f'Objdump mnemonic "{ref_mnemonic}" != "{our_mnemonic}" at address {ref_address}')
        sys.exit(1)
