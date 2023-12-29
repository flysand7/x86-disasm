
ODIN_FLAGS := "-o:none -debug -out:test.bin"

@prepare-disasm FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out

test TEST FILENAME: (prepare-disasm FILENAME)
    odin test src -test-name:test_{{TEST}} {{ODIN_FLAGS}} -- temp/temp.out

disasm FILENAME: (prepare-disasm FILENAME)
    odin test src -test-name:test_disasm {{ODIN_FLAGS}} -- temp/temp.out

dump FILENAME: (prepare-disasm FILENAME)
    odin test src -test-name:test_dump {{ODIN_FLAGS}} -- temp/temp.out

generate:
    ./src/generator.py

