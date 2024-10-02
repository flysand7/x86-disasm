#!/usr/bin/env lua

function table.slice(tbl, first, last, step)
    local sliced = {}
    for i = first or 1, last or #tbl, step or 1 do
      sliced[#sliced+1] = tbl[i]
    end
    return sliced
  end
  

function is_windows()
    return package.config:sub(1,1) == '\\'
end

function run_command(command)
    print('> ' .. command)
    local ok = os.execute(command)
    if not ok then
        os.exit(1)
    end
end

function odin_build(out, dir, options)
    if is_windows() then
        out = out .. '.exe'
    end
    run_command("odin build " .. dir .. " -out:"..out .. ' ' .. options)
end

function assemble(file)
    local in_file = 'test/asm/' .. file .. '.asm'
    local out_file = 'tmp/bin/' .. file
    run_command('nasm ' .. in_file .. ' -o '..out_file)
end

function disasm_run(file, options)
    local disasm_path
    if is_windows() then
        disasm_path = 'x86-disasm'
    else
        disasm_path = './x86-disasm'
    end
    run_command(disasm_path .. " " .. file .. ' ' .. options)
end

function build_tablegen(options)
    return odin_build('table-gen', 'tools/table_gen', '-collection:common=common ' .. options)
end

function run_tablegen(table, options)
    local tablegen_path
    if is_windows() then
        tablegen_path = 'table-gen'
    else
        tablegen_path = './table-gen'
    end
    run_command(tablegen_path .. ' ' .. table .. ' disasm/table_gen.odin ' .. options)
end

function build_disasm(flags)
    flags = flags .. ' -define:X86_USE_STUB=false'
    return odin_build('x86-disasm', 'cli', '-collection:common=common ' .. flags)
end

-------------------------------------------------------------------------------

local TABLE_PATH = './tables/encodings.txt'

local command = 'build'
local build_mode = 'debug'
if #arg == 0 then
    print('No arguments specified.')
    print('Assuming `./build.lua build -debug`')
else
    command = arg[1]
end

if command == 'build' then
    for i, flag in pairs(table.slice(arg, 2, #arg)) do
        if flag == '-release' then
            build_mode = 'release'
        elseif flag == '-debug' then
            build_mode = 'debug'
        end
    end
    local odin_flags = ''
    if build_mode == 'release' then
        odin_flags = odin_flags .. ' -o:aggressive -no-bounds-check'
    else
        odin_flags = odin_flags .. ' -debug'
    end
    build_tablegen(odin_flags)
    run_tablegen(TABLE_PATH, '')
    build_disasm(odin_flags)
elseif command == 'test' then
    local odin_flags = ''
    odin_flags = odin_flags .. ' -debug'
    build_tablegen(odin_flags)
    run_tablegen(TABLE_PATH, '')
    build_disasm(odin_flags)
    assemble('mov16')
    disasm_run('tmp/bin/mov16', '-cpu:16')
elseif command == 'test-inst' then
    local odin_flags = ''
    odin_flags = odin_flags .. ' -debug'
    build_tablegen(odin_flags)
    run_tablegen(TABLE_PATH, '')
    build_disasm(odin_flags)
    assemble('inst')
    disasm_run('tmp/bin/inst', '-cpu:16')
elseif command == 'inspect' then
    build_tablegen('-debug')
    local tablegen_flags = ''
    for i, flag in pairs(table.slice(arg, 2, #arg)) do
        tablegen_flags = tablegen_flags .. ' ' .. flag
    end
    run_tablegen(TABLE_PATH, tablegen_flags)
elseif command == 'inspect-inst' then
    build_tablegen('-debug')
    local tablegen_flags = ''
    for i, flag in pairs(table.slice(arg, 2, #arg)) do
        tablegen_flags = tablegen_flags .. ' ' .. flag
    end
    run_tablegen('./tables/entry.txt', tablegen_flags)
else
    print('== INVALID COMMAND: "' .. command .. '"')
end

print('== DONE == ')
