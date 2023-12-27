
ODIN_FLAGS := "-o:none -debug -out:test.bin"

test TEST FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out
    odin test src -test-name:test_{{TEST}} {{ODIN_FLAGS}} -- temp/temp.out

dump FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out
    odin test src -test-name:test_dump {{ODIN_FLAGS}} -- temp/temp.out

generate:
    ./src/generator.py

