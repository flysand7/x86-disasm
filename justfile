
ODIN_FLAGS := "-o:none -debug -out:test.bin"

prepare-disasm FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out

test TEST FILENAME: generate (prepare-disasm FILENAME)
    odin test disasm -test-name:test_{{TEST}} {{ODIN_FLAGS}} -- temp/temp.out

disasm FILENAME: generate (prepare-disasm FILENAME)
    odin test disasm -test-name:test_disasm {{ODIN_FLAGS}} -- temp/temp.out

dump FILENAME: generate (prepare-disasm FILENAME)
    odin test disasm -test-name:test_dump {{ODIN_FLAGS}} -- temp/temp.out

build-cli: generate
    odin build . -o:aggressive

time-cli: generate build-cli
    time ./x86-disasm x86-disasm > /dev/null

generate:
    ./disasm/table/generator.py

