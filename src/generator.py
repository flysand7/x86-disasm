#!/usr/bin/env python

TAB = '    '
PACKAGE_NAME = 'disasm'
TABLE_IN_FILENAME  = 'data/table.txt'
TABLE_OUT_FILENAME = 'src/table.odin'

def read_lines(path: str) -> list[str]:
    with open(path, 'r') as f:
        return list(f.readlines())

def write_split(file, split: str):
    if split[0] == '0' or split[0] == '1':
        split_bits = split
        split_len  = len(split)
        file.write(f'{3*TAB}Tab_Bits {{ 0b{split_bits}, {split_len} }},\n')
    elif split[0] == '-':
        ign_count = len(split)
        file.write(f'{3*TAB}Ign_Bits {{ {ign_count} }},\n')
    else:
        split_enum = split[0].upper() + split[1:]
        file.write(f'{3*TAB}Tab_Field.{split_enum},\n')

def write_line(file, splits: list[str]):
    # print(splits)
    inst = splits[0]
    op_bits = splits[1]
    op_len  = len(splits[1])
    file.write(f'{TAB}{{')
    file.write(f'\n{2*TAB}name = "{inst}",')
    file.write(f'\n{2*TAB}opcode = {{ 0b{op_bits}, {op_len} }},')
    mask_splits: list[str] = []
    flag_splits: list[str] = []
    for split in splits[2:]:
        if split[0] == '+':
            flag = split[1:]
            flag = flag[0].upper() + flag[1:]
            flag_splits.append(flag)
        else:
            mask_splits.append(split)
    file.write(f'\n{2*TAB}masks = {{\n')
    for split in mask_splits:
        write_split(file, split)
    file.write(f'{2*TAB}}},\n')
    if len(flag_splits) > 0:
        file.write(f'{2*TAB}flags = {{\n')
        for split in flag_splits:
            file.write(f'{3*TAB}.{split},\n')
        file.write(f'{2*TAB}}},\n')
    file.write(f'{TAB}}},\n')

def tokenize_line(splits: list[str], line: str):
    while len(line) > 0:
        if line[0] == '-':
            idx = 0
            while idx < len(line) and line[idx] == '-':
                idx += 1
            splits.append(line[:idx])
            line = line[idx:]
        elif line[0].isalpha() or line[0] == '_' or line[0] == '+':
            idx = 0
            while idx < len(line) and (line[idx].isdigit() or line[idx].isalpha() or line[idx] == '_' or line[0] == '+'):
                idx += 1
            splits.append(line[:idx])
            line = line[idx:]
        elif line[0].isdigit():
            idx = 0
            while idx < len(line) and line[idx].isdigit():
                idx += 1
            splits.append(line[:idx])
            while idx < len(line) and line[idx].isalpha():
                splits.append(line[idx])
                idx += 1
            line = line[idx:]
        else:
            line = line[1:]
            

out = open(TABLE_OUT_FILENAME, 'w')
out.write(f'package {PACKAGE_NAME}\n\n')
out.write(f'// THIS FILE IS AUTO-GENERATED FROM table.txt BY codegen.py\n\n')
out.write('decode_table := []Tab_Inst {\n')
for line in read_lines(TABLE_IN_FILENAME):
    line = line[:len(line)-1]
    if len(line) != 0 and line[0] != '#':
        splits = []
        tokenize_line(splits, line)
        write_line(out, splits)
out.write('}\n\n')
out.close()


