#!/usr/bin/env python

TAB = '    '
PACKAGE_NAME = 'disasm'
TABLE_IN_FILENAME  = 'data/table.txt'
TABLE_OUT_FILENAME = 'src/table.odin'

def read_lines(path: str) -> list[str]:
    with open(path, 'r') as f:
        return list(f.readlines())

def write_split(file, split: str):
    if split == ':':
        return
    if split[0] == '0' or split[0] == '1':
        split_bits = split
        split_len  = len(split)
        file.write(f'{2*TAB}Tab_Bits {{ 0b{split_bits}, {split_len} }},\n')
    elif split[0] == '-':
        ign_count = len(split)
        file.write(f'{2*TAB}Ign_Bits {{ {ign_count} }},\n')
    else:
        split_enum = split[0].upper() + split[1:]
        file.write(f'{2*TAB}Tab_Field.{split_enum},\n')

def write_line(file, splits: list[str]):
    inst = splits[0]
    op_bits = splits[1]
    op_len  = len(splits[1])
    file.write(f'{TAB}{{name = "{inst}", opcode = {{ 0b{op_bits}, {op_len} }}, masks = {{\n')
    for split in splits[2:]:
        write_split(file, split)
    file.write(f'{TAB}}}}},\n')

out = open(TABLE_OUT_FILENAME, 'w')
out.write(f'package {PACKAGE_NAME}\n\n')
out.write(f'// THIS FILE IS AUTO-GENERATED FROM table.txt BY codegen.py\n\n')
out.write('decode_table := []Tab_Inst {\n')
for line in read_lines(TABLE_IN_FILENAME):
    line = line[:len(line)-1]
    if len(line) != 0 and line[0] != '#':
        splits = [s for s in line.split(' ') if s]
        write_line(out, splits)
out.write('}\n\n')
out.close()


